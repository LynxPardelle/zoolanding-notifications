import copy
import json
import unittest

from tests.helpers import notification_event


class NotificationEventContractTests(unittest.TestCase):
    def test_accepts_the_exact_provider_neutral_contract(self):
        from src.contracts.events import parse_notification_event

        parsed = parse_notification_event(notification_event())

        self.assertEqual(parsed.event_id, "a" * 64)
        self.assertEqual(parsed.notification_policy_id, "billing-ops")
        self.assertEqual(parsed.source_id, "order-1")
        self.assertEqual(parsed.amount_minor, 90_000)
        self.assertEqual(parsed.currency, "MXN")
        self.assertEqual(len(parsed.event_hash), 64)

    def test_rejects_unknown_fields_sensitive_data_and_wrong_type_template_pairs(self):
        from src.contracts.events import EventContractError, parse_notification_event

        base = notification_event()
        invalid = []
        for key, value in (
            ("email", "operator@example.test"),
            ("body", "secret body"),
            ("secretRef", "/secret"),
            ("stripe", {"id": "provider-object"}),
            ("fiscal", {"rfc": "not-allowed"}),
        ):
            changed = copy.deepcopy(base)
            changed["data"][key] = value
            invalid.append(changed)
        changed = copy.deepcopy(base)
        changed["data"]["templateId"] = "payment-failed-v1"
        invalid.append(changed)
        changed = copy.deepcopy(base)
        changed["data"]["source"]["id"] = "order-other"
        invalid.append(changed)
        changed = copy.deepcopy(base)
        changed["eventType"] = "arbitrary.v1"
        invalid.append(changed)
        changed = copy.deepcopy(base)
        changed["data"]["variables"]["customerEmail"] = {
            "type": "string",
            "value": "operator@example.test",
        }
        invalid.append(changed)

        for value in invalid:
            with self.subTest(value=value), self.assertRaises(EventContractError):
                parse_notification_event(value)

    def test_rejects_malformed_bounds_and_dedupe_collisions(self):
        from src.contracts.events import EventContractError, parse_notification_event

        base = notification_event()
        invalid = []
        mutations = (
            ("eventId", "x" * 129),
            ("schemaVersion", True),
            ("occurredAt", True),
            ("environment", "dev"),
            ("domain", "bad domain"),
        )
        for key, value in mutations:
            changed = copy.deepcopy(base)
            changed[key] = value
            invalid.append(changed)
        changed = copy.deepcopy(base)
        changed["data"]["dedupeKey"] = "different"
        invalid.append(changed)
        changed = copy.deepcopy(base)
        changed["eventId"] = "event-1"
        changed["data"]["dedupeKey"] = "event-1"
        invalid.append(changed)
        changed = copy.deepcopy(base)
        changed["data"]["recipientSetVersion"] = True
        invalid.append(changed)
        changed = copy.deepcopy(base)
        changed["data"]["variables"]["amountMinor"]["value"] = 100_000_000
        invalid.append(changed)
        changed = copy.deepcopy(base)
        changed["data"]["variables"]["currency"]["value"] = "mxn"
        invalid.append(changed)

        for value in invalid:
            with self.subTest(value=value), self.assertRaises(EventContractError):
                parse_notification_event(value)

    def test_json_parser_rejects_duplicate_keys_and_non_finite_numbers(self):
        from src.contracts.events import EventContractError, parse_event_json

        for raw in (
            '{"schemaVersion":1,"schemaVersion":1}',
            '{"schemaVersion":NaN}',
            "[]",
            "not-json",
            '{"value":"\ud800"}',
        ):
            with self.subTest(raw=raw), self.assertRaises(EventContractError):
                parse_event_json(raw)

        parsed = parse_event_json(json.dumps(notification_event()))
        self.assertEqual(parsed.event_id, "a" * 64)


if __name__ == "__main__":
    unittest.main()
