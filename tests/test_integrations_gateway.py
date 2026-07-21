import copy
import importlib.util
import json
import unittest

from tests.helpers import SCOPE, notification_event, policy_descriptor


def parsed_event(**overrides):
    from src.contracts.events import parse_notification_event

    return parse_notification_event(notification_event(**overrides))


def resolved_policy():
    from src.common.published_policy import ResolvedNotificationPolicy

    return ResolvedNotificationPolicy(
        "test",
        SCOPE["tenantId"],
        SCOPE["draftId"],
        SCOPE["domain"],
        "version-1",
        "billing-ops",
        "mail-primary",
        "payment-succeeded",
        "payment-succeeded-v1",
        "billing-operators",
        1,
        "primary",
        5,
        None,
    )


def resolution(**overrides):
    value = {
        "connectionId": "mail-primary",
        "provider": "email.smtp",
        "mode": "test",
        "adapterVersion": "v1",
        "adapterId": "smtp2go-smtp-v1",
        "credentialReference": "/zoolanding/test/tenant-a/draft-a/notifications/smtp/mail-primary",
        "endpoint": {
            "host": "mail.smtp2go.com",
            "port": 465,
            "tlsMode": "implicit",
            "canonicalSendingDomain": "zoolandingpage.com.mx",
        },
        "senderPolicy": {
            "fromLocalPart": "notificaciones",
            "replyToLocalPart": "soporte",
        },
        "rateCircuitNamespace": "test-tenant-a-draft-a-mail-primary",
    }
    value.update(overrides)
    return value


class Invoke:
    def __init__(self, response=None):
        self.response = response or resolution()
        self.calls = []

    def __call__(self, path, payload):
        self.calls.append((path, copy.deepcopy(payload)))
        return copy.deepcopy(self.response)


class ConnectionResolutionTests(unittest.TestCase):
    def test_resolves_only_the_exact_aws_iam_command_and_smtp_boundary(self):
        from src.integrations_gateway import ConnectionResolver

        invoke = Invoke()
        connection = ConnectionResolver(invoke).resolve(parsed_event(), resolved_policy())

        self.assertEqual(connection.adapter_id, "smtp2go-smtp-v1")
        self.assertEqual(connection.host, "mail.smtp2go.com")
        self.assertEqual(connection.canonical_sending_domain, "zoolandingpage.com.mx")
        self.assertEqual(connection.from_address, "notificaciones@zoolandingpage.com.mx")
        self.assertEqual(connection.reply_to_address, "soporte@zoolandingpage.com.mx")
        self.assertEqual(invoke.calls[0][0], "/internal/v1/integrations/connection-resolve")
        request = invoke.calls[0][1]
        self.assertEqual(
            set(request),
            {"version", "scope", "connectionId", "commandId", "idempotencyKey", "input"},
        )
        self.assertEqual(request["scope"], notification_event()["data"] and SCOPE)
        self.assertEqual(request["input"], {"provider": "email.smtp", "capability": "send"})
        self.assertNotIn("@", repr(request))

    def test_rejects_wrong_endpoint_mode_domain_credential_and_extra_fields(self):
        from src.integrations_gateway import ConnectionResolutionError, ConnectionResolver

        invalid = []
        for key, value in (
            ("connectionId", "other"),
            ("provider", "stripe"),
            ("mode", "live"),
            ("adapterVersion", "v2"),
            ("adapterId", "other"),
            ("credentialReference", "/zoolanding/test/tenant-a/draft-b/notifications/smtp/mail-primary"),
            ("rateCircuitNamespace", "bad namespace"),
        ):
            invalid.append(resolution(**{key: value}))
        for key, value in (
            ("host", "smtp.example.test"),
            ("port", 587),
            ("tlsMode", "starttls"),
            ("canonicalSendingDomain", SCOPE["domain"]),
        ):
            changed = resolution()
            changed["endpoint"][key] = value
            invalid.append(changed)
        changed = resolution()
        changed["senderPolicy"]["fromLocalPart"] = "bad\r\nBcc"
        invalid.append(changed)
        changed = resolution()
        changed["senderPolicy"]["fromLocalPart"] = "billing..alerts"
        invalid.append(changed)
        invalid.append({**resolution(), "providerPayload": {}})

        for response in invalid:
            with self.subTest(response=response), self.assertRaises(ConnectionResolutionError):
                ConnectionResolver(Invoke(response)).resolve(parsed_event(), resolved_policy())

    def test_production_sender_is_exact_draft_domain_and_never_test(self):
        from src.common.published_policy import ResolvedNotificationPolicy
        from src.integrations_gateway import ConnectionResolutionError, ConnectionResolver

        event = parsed_event(environment="production", domain="draft.example.com")
        policy = ResolvedNotificationPolicy(
            "production", "tenant-a", "draft-a", "draft.example.com", "version-1",
            "billing-ops", "mail-primary", "payment-succeeded", "payment-succeeded-v1",
            "billing-operators", 1, "primary", 5, "approval-1",
        )
        response = resolution(
            mode="live",
            credentialReference="/zoolanding/production/tenant-a/draft-a/notifications/smtp/mail-primary",
        )
        response["endpoint"]["canonicalSendingDomain"] = "draft.example.com"
        self.assertEqual(
            ConnectionResolver(Invoke(response)).resolve(event, policy).canonical_sending_domain,
            "draft.example.com",
        )
        response["endpoint"]["canonicalSendingDomain"] = "zoolandingpage.com.mx"
        with self.assertRaises(ConnectionResolutionError):
            ConnectionResolver(Invoke(response)).resolve(event, policy)

    def test_signed_invoker_derives_origin_and_stage_signs_exact_path_and_rejects_duplicate_json(self):
        from src.integrations_gateway import (
            ConnectionResolutionError,
            SignedAWSIAMInvoker,
            _decode_json_response,
        )

        for api_id, environment, region, url_suffix in (
            ("short", "test", "us-east-1", "amazonaws.com"),
            ("ABCDEFGHIJ", "test", "us-east-1", "amazonaws.com"),
            ("abcdefghij", "dev", "us-east-1", "amazonaws.com"),
            ("abcdefghij", "test", "not-a-region", "amazonaws.com"),
            ("abcdefghij", "test", None, "amazonaws.com"),
            ("abcdefghij", "test", "us-east-1", "example.com"),
        ):
            with self.subTest(api_id=api_id, environment=environment, region=region), self.assertRaises(ConnectionResolutionError):
                SignedAWSIAMInvoker(api_id, environment, region, url_suffix)

        with self.assertRaises(ConnectionResolutionError):
            _decode_json_response(b'{"connectionId":"one","connectionId":"two"}')

        if importlib.util.find_spec("botocore") is None:
            return
        from botocore.credentials import Credentials

        class Response:
            status = 200

            def __init__(self, raw):
                self.raw = raw

            def read(self, amount):
                return self.raw[:amount]

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        class Opener:
            def __init__(self, raw):
                self.raw = raw
                self.calls = []

            def open(self, request, timeout):
                self.calls.append((request, timeout))
                return Response(self.raw)

        invoker = SignedAWSIAMInvoker(
            "abcdefghij",
            "test",
            "us-east-1",
            "amazonaws.com",
            lambda: Credentials("access", "secret", "token"),
        )
        opener = Opener(json.dumps(resolution()).encode("utf-8"))
        invoker._opener = opener
        self.assertEqual(invoker("/internal/v1/integrations/connection-resolve", {"version": 1}), resolution())
        request, timeout = opener.calls[0]
        self.assertEqual(request.full_url, "https://abcdefghij.execute-api.us-east-1.amazonaws.com/test/internal/v1/integrations/connection-resolve")
        self.assertEqual(timeout, 5)
        self.assertIn("Authorization", request.headers)



if __name__ == "__main__":
    unittest.main()
