import copy
from decimal import Decimal
import unittest

from tests.helpers import NOW
from tests.test_integrations_gateway import parsed_event, resolved_policy


class MemoryBackend:
    def __init__(self):
        self.items = {}
        self.calls = []

    @staticmethod
    def key(item):
        return item["pk"], item["sk"]

    def get(self, pk, sk):
        self.calls.append(("get", pk, sk))
        value = self.items.get((pk, sk))
        return copy.deepcopy(value)

    def put_if_absent(self, item):
        self.calls.append(("put_if_absent", copy.deepcopy(item)))
        key = self.key(item)
        if key in self.items:
            return False
        self.items[key] = copy.deepcopy(item)
        return True

    def compare_and_set(self, pk, sk, expected_revision, expected_state, updates, remove=()):
        self.calls.append(("compare_and_set", pk, sk, expected_revision, expected_state, copy.deepcopy(updates), tuple(remove)))
        item = self.items.get((pk, sk))
        if item is None or item.get("revision") != expected_revision or item.get("state") != expected_state:
            return False
        item.update(copy.deepcopy(updates))
        for key in remove:
            item.pop(key, None)
        item["revision"] += 1
        return True

    def increment_below(self, item, limit):
        self.calls.append(("increment_below", copy.deepcopy(item), limit))
        key = self.key(item)
        current = self.items.get(key)
        if current is None:
            current = copy.deepcopy(item)
            current["count"] = 0
            self.items[key] = current
        if current["count"] >= limit:
            return False
        current["count"] += 1
        return True

    def put(self, item):
        self.calls.append(("put", copy.deepcopy(item)))
        self.items[self.key(item)] = copy.deepcopy(item)


class DeliveryStoreTests(unittest.TestCase):
    def setUp(self):
        from src.delivery_store import DeliveryStore

        self.backend = MemoryBackend()
        self.store = DeliveryStore(self.backend)
        self.event = parsed_event()
        self.policy = resolved_policy()

    def test_prepares_minimal_90_day_ledger_and_binds_event_hash(self):
        record = self.store.prepare(self.event, self.policy, now_epoch=NOW)

        self.assertEqual(record["state"], "prepared")
        self.assertEqual(record["expiresAt"], NOW + 90 * 24 * 60 * 60)
        self.assertEqual(record["eventHash"], self.event.event_hash)
        self.assertEqual(record["maxAttempts"], 5)
        self.assertEqual(record["publishedVersionId"], "version-1")
        text = repr(record).lower()
        for forbidden in ("variables", "address", "username", "password", "body", "amountminor", "currency"):
            self.assertNotIn(forbidden, text)

        replay = self.store.prepare(self.event, self.policy, now_epoch=NOW + 1)
        self.assertEqual(replay, record)

        from dataclasses import replace
        from src.delivery_store import DeliveryConflict

        with self.assertRaises(DeliveryConflict):
            self.store.prepare(replace(self.event, event_hash="0" * 64), self.policy, now_epoch=NOW + 1)

    def test_rejects_corrupt_or_cross_event_delivery_receipts(self):
        from src.delivery_store import DeliveryConflict

        prepared = self.store.prepare(self.event, self.policy, now_epoch=NOW)
        key = self.backend.key(prepared)
        mutations = (
            ("eventHash", "b" * 64),
            ("publishedVersionId", "version-other"),
            ("notificationPolicyId", "other-policy"),
            ("notificationType", "payment-failed"),
            ("templateId", "payment-failed-v1"),
            ("recipientSetId", "other-set"),
            ("recipientSetVersion", 2),
            ("recipientMemberId", "secondary"),
            ("sourceType", "other-source"),
            ("sourceId", "order-other"),
            ("connectionId", "BAD CONNECTION"),
            ("updatedAt", NOW - 1),
            ("reconciliationApprovalId", "bad approval"),
        )
        for field, value in mutations:
            self.backend.items[key] = copy.deepcopy(prepared)
            self.backend.items[key][field] = value
            with self.subTest(field=field), self.assertRaises(DeliveryConflict):
                self.store.get(self.event)

        self.backend.items[key] = copy.deepcopy(prepared)
        sending = self.store.claim(self.event, max_attempts=5, now_epoch=NOW + 1).record
        self.backend.items[key]["leaseExpiresAt"] = sending["leaseExpiresAt"] + 1
        with self.assertRaises(DeliveryConflict):
            self.store.get(self.event)

        self.backend.items[key] = copy.deepcopy(sending)
        accepted = self.store.mark_accepted(self.event, now_epoch=NOW + 2)
        for field, value in (("reasonCode", "smtp_quota"), ("acceptedAt", "not-an-epoch")):
            self.backend.items[key] = copy.deepcopy(accepted)
            self.backend.items[key][field] = value
            with self.subTest(accepted_field=field), self.assertRaises(DeliveryConflict):
                self.store.get(self.event)

    def test_claims_with_a_conditional_lease_and_stale_sending_becomes_uncertain(self):
        self.store.prepare(self.event, self.policy, now_epoch=NOW)
        first_claim = self.store.claim(self.event, max_attempts=5, now_epoch=NOW + 1)
        self.assertTrue(first_claim.acquired)
        sending = first_claim.record
        self.assertEqual((sending["state"], sending["attempts"]), ("sending", 1))
        self.assertEqual(sending["leaseExpiresAt"], NOW + 46)

        duplicate_claim = self.store.claim(self.event, max_attempts=5, now_epoch=NOW + 2)
        self.assertFalse(duplicate_claim.acquired)
        still_sending = duplicate_claim.record
        self.assertEqual(still_sending["state"], "sending")

        stale_claim = self.store.claim(self.event, max_attempts=5, now_epoch=NOW + 47)
        self.assertFalse(stale_claim.acquired)
        stale = stale_claim.record
        self.assertEqual(stale["state"], "uncertain")
        self.assertEqual(stale["reasonCode"], "stale_sending_lease")

    def test_enforces_transition_states_and_maximum_attempts(self):
        from dataclasses import replace
        from src.delivery_store import DeliveryConflict

        one_attempt_policy = replace(self.policy, max_attempts=1)
        self.store.prepare(self.event, one_attempt_policy, now_epoch=NOW)
        with self.assertRaises(DeliveryConflict):
            self.store.mark_accepted(self.event, now_epoch=NOW + 1)

        self.store.claim(self.event, max_attempts=1, now_epoch=NOW + 1)
        exhausted = self.store.mark_retryable(self.event, max_attempts=1, now_epoch=NOW + 2)
        self.assertEqual((exhausted["state"], exhausted["reasonCode"]), ("failed", "retry_exhausted"))
        exhausted_claim = self.store.claim(self.event, max_attempts=1, now_epoch=NOW + 3)
        self.assertFalse(exhausted_claim.acquired)
        self.assertEqual(exhausted_claim.record["state"], "failed")

        with self.assertRaises(DeliveryConflict):
            self.store.claim(self.event, max_attempts=5, now_epoch=NOW + 4)

    def test_conditional_draft_and_connection_rate_limits_are_independent(self):
        from src.delivery_store import (
            CONNECTIONS_PER_MINUTE,
            DRAFT_PER_MINUTE,
            DeliveryStore,
            RateLimitExceeded,
        )

        for _ in range(DRAFT_PER_MINUTE):
            self.store.reserve_rate(self.event, "namespace-a", now_epoch=NOW)
        with self.assertRaises(RateLimitExceeded):
            self.store.reserve_rate(self.event, "namespace-b", now_epoch=NOW)

        aggregate_backend = MemoryBackend()
        aggregate_store = DeliveryStore(aggregate_backend)
        for suffix in ("a", "b", "c", "d", "e"):
            other = parsed_event(
                draftId=f"draft-{suffix}",
                domain=f"draft-{suffix}.example.test",
            )
            for _ in range(DRAFT_PER_MINUTE):
                aggregate_store.reserve_rate(other, "namespace-a", now_epoch=NOW)

        connection_bucket = next(
            item
            for item in aggregate_backend.items.values()
            if item.get("itemType") == "NotificationConnectionRateBucket"
        )
        self.assertEqual(connection_bucket["count"], CONNECTIONS_PER_MINUTE)
        candidate = parsed_event(
            draftId="draft-f",
            domain="draft-f.example.test",
        )
        calls_before_rejection = len(aggregate_backend.calls)
        with self.assertRaises(RateLimitExceeded):
            aggregate_store.reserve_rate(candidate, "namespace-a", now_epoch=NOW)
        rejection_calls = aggregate_backend.calls[calls_before_rejection:]
        self.assertEqual(len(rejection_calls), 2)
        self.assertEqual(rejection_calls[0][1]["itemType"], "NotificationRateBucket")
        self.assertEqual(
            rejection_calls[1][1]["itemType"],
            "NotificationConnectionRateBucket",
        )

    def test_auth_and_quota_circuit_is_scoped_and_contains_no_provider_text(self):
        self.assertFalse(self.store.circuit_open(self.event, "namespace-a"))
        opened = self.store.open_circuit(self.event, "namespace-a", "smtp_authentication", now_epoch=NOW)
        self.assertTrue(self.store.circuit_open(self.event, "namespace-a"))
        self.assertEqual(opened["reasonCode"], "smtp_authentication")
        self.assertNotIn("response", repr(opened).lower())

        other = parsed_event(draftId="draft-b", domain="draft-b.example.test")
        self.assertFalse(self.store.circuit_open(other, "namespace-a"))

        key = next(key for key, value in self.backend.items.items() if value.get("itemType") == "NotificationCircuit")
        self.backend.items[key]["state"] = "corrupt"
        from src.delivery_store import DeliveryConflict
        with self.assertRaises(DeliveryConflict):
            self.store.circuit_open(self.event, "namespace-a")

    def test_dynamo_backend_uses_consistent_conditional_operations_only(self):
        from src.delivery_store import DynamoDeliveryBackend

        class Table:
            def __init__(self):
                self.calls = []

            def get_item(self, **kwargs):
                self.calls.append(("get_item", kwargs))
                return {"Item": {"pk": "p", "sk": "s"}}

            def put_item(self, **kwargs):
                self.calls.append(("put_item", kwargs))
                return {}

            def update_item(self, **kwargs):
                self.calls.append(("update_item", kwargs))
                return {}

        table = Table()
        backend = DynamoDeliveryBackend(table)
        self.assertEqual(backend.get("p", "s"), {"pk": "p", "sk": "s"})
        self.assertTrue(backend.put_if_absent({"pk": "p", "sk": "s"}))
        self.assertTrue(backend.compare_and_set("p", "s", 1, "prepared", {"state": "sending"}))
        self.assertTrue(backend.increment_below({"pk": "p", "sk": "rate", "itemType": "Rate", "expiresAt": NOW}, 20))
        self.assertEqual([name for name, _request in table.calls], ["get_item", "put_item", "update_item", "update_item"])
        self.assertTrue(table.calls[0][1]["ConsistentRead"])
        self.assertIn("attribute_not_exists", table.calls[1][1]["ConditionExpression"])
        self.assertIn("#revision = :expected_revision", table.calls[2][1]["ConditionExpression"])
        rate_values = table.calls[3][1]["ExpressionAttributeValues"]
        self.assertNotIn(":zero", rate_values)

    def test_dynamo_backend_normalizes_only_expected_integral_decimal_numbers(self):
        from src.delivery_store import DeliveryConflict, DynamoDeliveryBackend

        prepared = self.store.prepare(self.event, self.policy, now_epoch=NOW)
        numeric_fields = {
            "recipientSetVersion", "attempts", "maxAttempts", "revision",
            "createdAt", "updatedAt", "expiresAt",
        }
        decimal_item = {
            key: Decimal(value) if key in numeric_fields else copy.deepcopy(value)
            for key, value in prepared.items()
        }

        class Table:
            def __init__(self, item):
                self.item = item

            def get_item(self, **kwargs):
                del kwargs
                return {"Item": copy.deepcopy(self.item)}

        normalized = DynamoDeliveryBackend(Table(decimal_item)).get(
            prepared["pk"],
            prepared["sk"],
        )
        self.assertEqual(normalized, prepared)
        self.assertTrue(all(type(normalized[field]) is int for field in numeric_fields))

        invalid_values = (Decimal("1.5"), Decimal("1e30"), True, 1.0, "1")
        for invalid in invalid_values:
            changed = copy.deepcopy(decimal_item)
            changed["attempts"] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(DeliveryConflict):
                DynamoDeliveryBackend(Table(changed)).get(prepared["pk"], prepared["sk"])

        changed = copy.deepcopy(decimal_item)
        changed["unexpectedNumber"] = Decimal(1)
        with self.assertRaises(DeliveryConflict):
            DynamoDeliveryBackend(Table(changed)).get(prepared["pk"], prepared["sk"])

        for item in (
            {
                "itemType": "NotificationRateBucket",
                "bucketMinute": Decimal(NOW // 60),
                "expiresAt": Decimal(NOW + 1),
                "count": Decimal(1),
            },
            {
                "itemType": "NotificationCircuit",
                "openedAt": Decimal(NOW),
                "expiresAt": Decimal(NOW + 1),
            },
        ):
            normalized = DynamoDeliveryBackend(Table(item)).get("pk", "sk")
            self.assertTrue(all(type(value) is int for key, value in normalized.items() if key != "itemType"))


if __name__ == "__main__":
    unittest.main()
