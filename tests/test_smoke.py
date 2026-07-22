import json
import unittest
from unittest.mock import patch


class SSM:
    def __init__(self, *, parameters=None, invalid=None, error=None):
        self.parameters = parameters or []
        self.invalid = invalid or []
        self.error = error
        self.calls = []

    def get_parameters(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return {"Parameters": self.parameters, "InvalidParameters": self.invalid}


class ProviderError(Exception):
    def __init__(self, code, message="sensitive provider detail"):
        super().__init__(message)
        self.response = {"Error": {"Code": code, "Message": message}}


class NoCredentialsError(Exception):
    pass


def values(environment="test"):
    from tools.notification_readiness_smoke import expected_parameter_paths

    paths = expected_parameter_paths(environment)
    resolved = {
        "config_registry_table": "zoolanding-config-registry-test",
        "config_payload_bucket": "zoolanding-config-payloads-test",
        "commerce_topic_arn": "arn:aws:sns:us-east-1:123456789012:commerce-notifications-test",
        "integrations_api_id": "abc123def4",
        "smtp_worker_role_arn": "arn:aws:iam::123456789012:role/zoolanding-notifications-test-worker",
        "notification_queue_arn": "arn:aws:sqs:us-east-1:123456789012:zoolanding-notifications-test",
        "delivery_ledger_name": "zoolanding-notifications-test-ledger",
    }
    return [{"Name": paths[key], "Type": "String", "Value": value} for key, value in resolved.items()]


class NotificationReadinessSmokeTests(unittest.TestCase):
    def test_ready_reads_only_exact_plaintext_identifiers(self):
        from tools.notification_readiness_smoke import run_smoke

        client = SSM(parameters=values())
        result = run_smoke("test", "us-east-1", client)

        self.assertEqual(result, {"ok": True, "category": "ready"})
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.calls[0]["WithDecryption"], False)
        self.assertEqual(len(client.calls[0]["Names"]), 7)
        self.assertTrue(all(name.startswith("/zoolanding/test/") for name in client.calls[0]["Names"]))

    def test_categories_are_closed_and_never_expose_provider_details(self):
        from tools.notification_readiness_smoke import run_smoke

        cases = (
            (("dev", "us-east-1", SSM()), "missing_input"),
            (("test", "bad region", SSM()), "missing_input"),
            (("test", "us-east-1", SSM(error=ProviderError("AccessDeniedException"))), "auth_failure"),
            (("test", "us-east-1", SSM(error=NoCredentialsError("sensitive profile"))), "auth_failure"),
            (("test", "us-east-1", SSM(invalid=["/zoolanding/test/config/registry-table-name"])), "propagation_delay"),
            (("test", "us-east-1", SSM(parameters=values()[:-1])), "propagation_delay"),
            (("test", "us-east-1", SSM(parameters=[{**item, "Value": "*"} for item in values()])), "configuration_failure"),
            (("test", "us-east-1", SSM(error=ProviderError("ServiceUnavailable", "secret text"))), "provider_failure"),
        )
        for arguments, expected in cases:
            with self.subTest(expected=expected):
                result = run_smoke(*arguments)
                rendered = json.dumps(result)
                self.assertEqual(result, {"ok": False, "category": expected})
                self.assertNotIn("secret", rendered)
                self.assertNotIn("AccessDenied", rendered)
                self.assertEqual(set(result), {"ok", "category"})

    def test_cli_prints_only_redacted_result_and_never_creates_client_for_missing_input(self):
        from tools import notification_readiness_smoke

        with patch("builtins.print") as output, patch.object(notification_readiness_smoke, "_ssm_client") as factory:
            status = notification_readiness_smoke.main([])

        self.assertEqual(status, 2)
        factory.assert_not_called()
        output.assert_called_once_with('{"category":"missing_input","ok":false}')


if __name__ == "__main__":
    unittest.main()
