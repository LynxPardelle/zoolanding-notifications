import copy
import json
import unittest

from tests.helpers import notification_event
from tests.test_integrations_gateway import Invoke, parsed_event, resolution, resolved_policy


SMTP_PATH = "/zoolanding/test/tenant-a/draft-a/notifications/smtp/mail-primary"
RECIPIENT_PATH = "/zoolanding/test/tenant-a/draft-a/notifications/recipients/billing-operators/1/primary"


def tags(purpose, **extra):
    values = {
        "zoolanding:environment": "test",
        "zoolanding:tenant-id": "tenant-a",
        "zoolanding:draft-id": "draft-a",
        "zoolanding:secret-purpose": purpose,
        "zoolanding:enabled": "true",
    }
    values.update(extra)
    return [{"Key": key, "Value": value} for key, value in values.items()]


class SecretClient:
    def __init__(self):
        self.calls = []
        self.descriptions = {
            SMTP_PATH: {
                "Name": SMTP_PATH,
                "Tags": tags("smtp", **{
                    "zoolanding:connection-id": "mail-primary",
                    "zoolanding:smtp-account-isolation-id": "account:test:primary",
                    "zoolanding:smtp-credential-isolation-id": "credential:test:primary",
                }),
            },
            RECIPIENT_PATH: {
                "Name": RECIPIENT_PATH,
                "Tags": tags(
                    "recipient",
                    **{
                        "zoolanding:recipient-set-id": "billing-operators",
                        "zoolanding:recipient-set-version": "1",
                        "zoolanding:recipient-member-id": "primary",
                    },
                ),
            },
        }
        self.values = {
            SMTP_PATH: {"version": 1, "username": "smtp-user", "password": "smtp-password"},
            RECIPIENT_PATH: {"version": 1, "address": "operator@example.test"},
        }

    def describe_secret(self, *, SecretId):
        self.calls.append(("describe", SecretId))
        return copy.deepcopy(self.descriptions[SecretId])

    def get_secret_value(self, *, SecretId):
        self.calls.append(("get", SecretId))
        return {"SecretString": json.dumps(self.values[SecretId])}


def connection():
    from src.integrations_gateway import ConnectionResolver

    return ConnectionResolver(Invoke(resolution())).resolve(parsed_event(), resolved_policy())


class SecretBoundaryTests(unittest.TestCase):
    def test_describes_exact_tags_before_getting_each_secret_on_every_attempt(self):
        from src.secret_resolver import SecretResolver

        client = SecretClient()
        resolver = SecretResolver(client)
        smtp = resolver.smtp(parsed_event(), connection())
        recipient = resolver.recipient(parsed_event())
        resolver.smtp(parsed_event(), connection())

        self.assertEqual(smtp.username, "smtp-user")
        self.assertEqual(recipient.address, "operator@example.test")
        self.assertEqual(
            client.calls,
            [
                ("describe", SMTP_PATH), ("get", SMTP_PATH),
                ("describe", RECIPIENT_PATH), ("get", RECIPIENT_PATH),
                ("describe", SMTP_PATH), ("get", SMTP_PATH),
            ],
        )

    def test_current_disabled_deleted_or_cross_scope_tag_blocks_before_value_read(self):
        from src.secret_resolver import SecretResolutionError, SecretResolver

        mutations = (
            ("tag", "zoolanding:enabled", "false"),
            ("tag", "zoolanding:draft-id", "draft-other"),
            ("tag", "zoolanding:smtp-account-isolation-id", "short"),
            ("tag", "zoolanding:smtp-credential-isolation-id", "bad value with spaces"),
            ("deleted", None, None),
        )
        for kind, key, value in mutations:
            client = SecretClient()
            if kind == "tag":
                next(item for item in client.descriptions[SMTP_PATH]["Tags"] if item["Key"] == key)["Value"] = value
            else:
                client.descriptions[SMTP_PATH]["DeletedDate"] = "later"
            with self.subTest(kind=kind), self.assertRaises(SecretResolutionError):
                SecretResolver(client).smtp(parsed_event(), connection())
            self.assertEqual(client.calls, [("describe", SMTP_PATH)])

        client = SecretClient()
        client.descriptions[SMTP_PATH]["Tags"] = [
            tag for tag in client.descriptions[SMTP_PATH]["Tags"]
            if tag["Key"] != "zoolanding:smtp-account-isolation-id"
        ]
        with self.assertRaises(SecretResolutionError):
            SecretResolver(client).smtp(parsed_event(), connection())
        self.assertEqual(client.calls, [("describe", SMTP_PATH)])

    def test_rejects_malformed_secret_values_without_echoing_them(self):
        from src.secret_resolver import SecretResolutionError, SecretResolver

        invalid = (
            {"version": 1, "username": "smtp-user", "password": "smtp-password", "extra": "x"},
            {"version": True, "username": "smtp-user", "password": "smtp-password"},
            {"version": 2, "username": "smtp-user", "password": "smtp-password"},
            {"version": 1, "username": "smtp-user\n", "password": "smtp-password"},
            {"version": 1, "username": "smtp-user", "password": ""},
        )
        for value in invalid:
            client = SecretClient()
            client.values[SMTP_PATH] = value
            with self.subTest(value=value) as context:
                with self.assertRaises(SecretResolutionError) as raised:
                    SecretResolver(client).smtp(parsed_event(), connection())
                self.assertNotIn("smtp-password", str(raised.exception))

        for address in (
            "",
            "display <operator@example.test>",
            "two@@example.test",
            "operator@localhost",
            "a\n@example.test",
            ".a@example.test",
            "a.@example.test",
            "a..b@example.test",
        ):
            client = SecretClient()
            client.values[RECIPIENT_PATH] = {"version": 1, "address": address}
            with self.subTest(address=address), self.assertRaises(SecretResolutionError):
                SecretResolver(client).recipient(parsed_event())

        client = SecretClient()
        client.values[RECIPIENT_PATH] = {"version": True, "address": "operator@example.test"}
        with self.assertRaises(SecretResolutionError):
            SecretResolver(client).recipient(parsed_event())


if __name__ == "__main__":
    unittest.main()
