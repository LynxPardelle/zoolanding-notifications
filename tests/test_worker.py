import copy
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
import json
import threading
import unittest

from tests.helpers import NOW, notification_event
from tests.test_delivery_store import MemoryBackend
from tests.test_integrations_gateway import Invoke, parsed_event, resolution, resolved_policy
from tests.test_secrets import SecretClient


class PolicyResolver:
    def __init__(self, calls, error=None):
        self.calls = calls
        self.error = error

    def resolve(self, event):
        self.calls.append("policy")
        if self.error:
            raise self.error
        return resolved_policy()


class ConnectionResolver:
    def __init__(self, calls):
        from src.integrations_gateway import ConnectionResolver as RealResolver

        self.calls = calls
        self.real = RealResolver(Invoke(resolution()))

    def resolve(self, event, policy):
        self.calls.append("connection")
        return self.real.resolve(event, policy)


class Secrets:
    def __init__(self, calls, client=None):
        from src.secret_resolver import SecretResolver

        self.calls = calls
        self.real = SecretResolver(client or SecretClient())

    def smtp(self, event, connection):
        self.calls.append("smtp-secret")
        return self.real.smtp(event, connection)

    def recipient(self, event):
        self.calls.append("recipient-secret")
        return self.real.recipient(event)


class SMTP:
    def __init__(self, calls, results):
        self.calls = calls
        self.results = list(results)

    def send(self, connection, credentials, message):
        del connection, credentials, message
        self.calls.append("smtp")
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class Metrics:
    def __init__(self):
        self.circuits = []
        self.throttles = []
        self.mismatches = []

    def circuit_opened(self, environment, reason_code):
        self.circuits.append((environment, reason_code))

    def smtp_throttled(self, environment):
        self.throttles.append(environment)

    def test_live_mismatch(self, environment):
        self.mismatches.append(environment)


def result(outcome, reason):
    from src.smtp_adapter import SMTPResult

    return SMTPResult(outcome, reason)


class NotificationWorkerTests(unittest.TestCase):
    def worker(self, results, *, policy_error=None, backend=None, secret_client=None):
        from src.delivery_store import DeliveryStore
        from src.domain.delivery import NotificationWorker

        self.calls = []
        self.backend = backend or MemoryBackend()
        self.store = DeliveryStore(self.backend)
        self.metrics = Metrics()
        return NotificationWorker(
            PolicyResolver(self.calls, policy_error),
            ConnectionResolver(self.calls),
            Secrets(self.calls, secret_client),
            self.store,
            SMTP(self.calls, results),
            self.metrics,
        )

    def test_policy_and_complete_tuple_precede_every_secret_or_smtp_access(self):
        from src.common.published_policy import PolicyResolutionError

        worker = self.worker([], policy_error=PolicyResolutionError("safe"))
        self.assertEqual(worker.process(parsed_event(), now_epoch=NOW), "retry")
        self.assertEqual(self.calls, ["policy"])
        self.assertEqual(self.backend.items, {})

        worker = self.worker([result("accepted_by_smtp", "smtp_accepted")])
        self.assertEqual(worker.process(parsed_event(), now_epoch=NOW), "processed")
        self.assertEqual(
            self.calls,
            ["policy", "connection", "smtp-secret", "recipient-secret", "smtp"],
        )

    def test_realistic_dynamodb_decimals_complete_prepare_claim_send_and_terminal_read(self):
        from src.delivery_store import _normalize_dynamodb_item

        numeric_fields = {
            "recipientSetVersion", "attempts", "maxAttempts", "revision",
            "createdAt", "updatedAt", "expiresAt", "leaseExpiresAt",
            "acceptedAt", "uncertainAt", "failedAt", "openedAt", "bucketMinute", "count",
        }

        class DecimalBackend(MemoryBackend):
            def get(self, pk, sk):
                item = super().get(pk, sk)
                if item is None:
                    return None
                converted = {
                    key: Decimal(value)
                    if key in numeric_fields and type(value) is int
                    else value
                    for key, value in item.items()
                }
                return _normalize_dynamodb_item(converted)

        backend = DecimalBackend()
        worker = self.worker([result("accepted_by_smtp", "smtp_accepted")], backend=backend)

        self.assertEqual(worker.process(parsed_event(), now_epoch=NOW), "processed")
        terminal = self.store.get(parsed_event())
        self.assertEqual(terminal["state"], "accepted_by_smtp")
        self.assertIs(type(terminal["attempts"]), int)
        self.store.open_circuit(
            parsed_event(),
            "test-tenant-a-draft-a-mail-primary",
            "smtp_quota",
            now_epoch=NOW + 1,
        )
        self.assertTrue(
            self.store.circuit_open(parsed_event(), "test-tenant-a-draft-a-mail-primary")
        )

    def test_duplicate_sqs_delivery_returns_the_accepted_receipt_without_resend(self):
        worker = self.worker([result("accepted_by_smtp", "smtp_accepted")])
        self.assertEqual(worker.process(parsed_event(), now_epoch=NOW), "processed")
        self.assertEqual(worker.process(parsed_event(), now_epoch=NOW + 1), "processed")
        self.assertEqual(self.calls.count("smtp"), 1)

    def test_two_workers_racing_for_one_prepared_delivery_have_one_smtp_owner(self):
        from src.delivery_store import DeliveryStore
        from src.domain.delivery import NotificationWorker

        event = parsed_event()
        backend = MemoryBackend()
        store = DeliveryStore(backend)
        store.prepare(event, resolved_policy(), now_epoch=NOW)
        barrier = threading.Barrier(2)

        class BarrierStore:
            def __getattr__(self, name):
                return getattr(store, name)

            def claim(self, *args, **kwargs):
                barrier.wait(timeout=5)
                return store.claim(*args, **kwargs)

        class CountingSMTP:
            def __init__(self):
                self.count = 0
                self.lock = threading.Lock()

            def send(self, connection, credentials, message):
                del connection, credentials, message
                with self.lock:
                    self.count += 1
                return result("accepted_by_smtp", "smtp_accepted")

        smtp = CountingSMTP()

        def build_worker():
            calls = []
            return NotificationWorker(
                PolicyResolver(calls),
                ConnectionResolver(calls),
                Secrets(calls),
                BarrierStore(),
                smtp,
                Metrics(),
            )

        workers = (build_worker(), build_worker())
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda worker: worker.process(event, now_epoch=NOW + 1), workers))

        self.assertEqual(smtp.count, 1)
        self.assertTrue(all(outcome in {"processed", "retry"} for outcome in outcomes))
        self.assertIn("processed", outcomes)
        self.assertEqual(store.get(event)["state"], "accepted_by_smtp")

    def test_crash_after_smtp_acceptance_stales_to_uncertain_without_blind_resend(self):
        worker = self.worker([result("accepted_by_smtp", "smtp_accepted")])
        original = self.store.mark_accepted

        def lost_commit(*args, **kwargs):
            raise RuntimeError("lost commit")

        self.store.mark_accepted = lost_commit
        self.assertEqual(worker.process(parsed_event(), now_epoch=NOW), "retry")
        self.store.mark_accepted = original
        self.assertEqual(worker.process(parsed_event(), now_epoch=NOW + 46), "retry")
        record = self.store.get(parsed_event())
        self.assertEqual(record["state"], "uncertain")
        self.assertEqual(self.calls.count("smtp"), 1)

    def test_ambiguous_timeout_is_uncertain_and_never_retried(self):
        worker = self.worker([result("uncertain", "smtp_ambiguous")])
        self.assertEqual(worker.process(parsed_event(), now_epoch=NOW), "retry")
        self.assertEqual(worker.process(parsed_event(), now_epoch=NOW + 100), "retry")
        self.assertEqual(self.store.get(parsed_event())["state"], "uncertain")
        self.assertEqual(self.calls.count("smtp"), 1)

    def test_confirmed_4xx_retries_only_to_policy_limit_and_5xx_is_permanent(self):
        worker = self.worker([
            result("retryable", "smtp_transient") for _ in range(5)
        ])
        for offset in range(5):
            self.assertEqual(worker.process(parsed_event(), now_epoch=NOW + offset), "retry")
        self.assertEqual(self.store.get(parsed_event())["state"], "failed")
        self.assertEqual(self.store.get(parsed_event())["attempts"], 5)
        self.assertEqual(worker.process(parsed_event(), now_epoch=NOW + 6), "retry")
        self.assertEqual(self.calls.count("smtp"), 5)

        worker = self.worker([result("failed", "smtp_permanent")])
        self.assertEqual(worker.process(parsed_event(), now_epoch=NOW), "retry")
        self.assertEqual(worker.process(parsed_event(), now_epoch=NOW + 1), "retry")
        self.assertEqual(self.calls.count("smtp"), 1)

    def test_auth_and_quota_failures_open_the_connection_circuit(self):
        for reason in ("smtp_authentication", "smtp_quota"):
            worker = self.worker([result("failed", reason)])
            with self.subTest(reason=reason):
                self.assertEqual(worker.process(parsed_event(), now_epoch=NOW), "retry")
                self.assertTrue(self.store.circuit_open(parsed_event(), "test-tenant-a-draft-a-mail-primary"))
                self.assertEqual(self.metrics.circuits, [("test", reason)])
                self.assertEqual(worker.process(parsed_event(), now_epoch=NOW + 1), "retry")
                self.assertEqual(self.calls.count("smtp"), 1)

    def test_smtp2go_throttle_is_retryable_and_emits_a_separate_metric(self):
        worker = self.worker([result("retryable", "smtp_throttled")])

        self.assertEqual(worker.process(parsed_event(), now_epoch=NOW), "retry")
        self.assertEqual(self.metrics.throttles, ["test"])
        self.assertEqual(self.metrics.circuits, [])
        self.assertFalse(self.store.circuit_open(parsed_event(), "test-tenant-a-draft-a-mail-primary"))

    def test_current_recipient_revocation_blocks_before_smtp(self):
        client = SecretClient()
        client.descriptions[next(key for key in client.descriptions if "/recipients/" in key)]["Tags"] = [
            {**tag, "Value": "false"} if tag["Key"] == "zoolanding:enabled" else tag
            for tag in client.descriptions[next(key for key in client.descriptions if "/recipients/" in key)]["Tags"]
        ]
        worker = self.worker([], secret_client=client)
        self.assertEqual(worker.process(parsed_event(), now_epoch=NOW), "retry")
        self.assertNotIn("smtp", self.calls)
        self.assertEqual(self.store.get(parsed_event())["state"], "failed")

    def test_batch_reports_malformed_failed_and_uncertain_records_for_dlq(self):
        from src.handlers.smtp_delivery_worker import process_batch

        worker = self.worker([result("accepted_by_smtp", "smtp_accepted")])
        good = notification_event()
        bad = copy.deepcopy(good)
        bad["data"]["email"] = "operator@example.test"
        batch = {
            "Records": [
                {"messageId": "good", "body": json.dumps(good)},
                {"messageId": "bad-json", "body": "{"},
                {"messageId": "bad-contract", "body": json.dumps(bad)},
            ]
        }
        self.assertEqual(
            process_batch(batch, worker, now_epoch=NOW, expected_environment="test"),
            {"batchItemFailures": [
                {"itemIdentifier": "bad-json"},
                {"itemIdentifier": "bad-contract"},
            ]},
        )

        wrong_env = notification_event(environment="production", domain="draft.example.com")
        self.assertEqual(
            process_batch(
                {"Records": [{"messageId": "wrong-env", "body": json.dumps(wrong_env)}]},
                worker,
                now_epoch=NOW,
                expected_environment="test",
            ),
            {"batchItemFailures": [{"itemIdentifier": "wrong-env"}]},
        )
        self.assertEqual(self.metrics.mismatches, ["test"])

        with self.assertRaises(ValueError):
            process_batch({}, worker, now_epoch=NOW, expected_environment="test")
        for malformed in (
            {"Records": [{"body": json.dumps(good)}]},
            {"Records": [
                {"messageId": "duplicate", "body": json.dumps(good)},
                {"messageId": "duplicate", "body": json.dumps(good)},
            ]},
        ):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                process_batch(malformed, worker, now_epoch=NOW, expected_environment="test")


if __name__ == "__main__":
    unittest.main()
