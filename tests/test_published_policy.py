import copy
import hashlib
import json
import unittest

from tests.helpers import (
    FakeRegistry,
    FakeS3,
    SCOPE,
    canonical_bytes,
    notification_event,
    package_objects,
    policy_descriptor,
)


class PublishedNotificationPolicyTests(unittest.TestCase):
    def resolver(self, descriptor=None, registry=None, objects=None):
        from src.common.published_policy import PublishedPolicyResolver

        registry = registry or FakeRegistry()
        s3 = FakeS3(objects or package_objects(descriptor))
        return PublishedPolicyResolver(registry, s3, "config-bucket"), registry, s3

    def event(self):
        from src.contracts.events import parse_notification_event

        return parse_notification_event(notification_event())

    def test_uses_exact_event_version_and_ignores_the_current_pointer(self):
        resolver, registry, s3 = self.resolver()

        policy = resolver.resolve(self.event())

        self.assertEqual(policy.version_id, "version-1")
        self.assertEqual(policy.connection_id, "mail-primary")
        self.assertEqual(policy.max_attempts, 5)
        self.assertTrue(registry.calls[0]["ConsistentRead"])
        self.assertEqual(
            [key for _bucket, key in s3.calls],
            [
                f"sites/{SCOPE['domain']}/versions/version-1/_manifest.json",
                f"sites/{SCOPE['domain']}/versions/version-1/{SCOPE['domain']}/server/notification-policies.json",
            ],
        )

        registry.item["publishedEnvironments"]["test"] = {
            "versionId": "new-current-version",
            "prefix": "sites/not-used/",
        }
        replay = resolver.resolve(self.event())
        self.assertEqual(replay, policy)
        self.assertEqual(len(registry.calls), 2, "metadata scope must be fresh on every retry")
        self.assertEqual(len(s3.calls), 2, "only exact version bodies may be cached")

    def test_cache_is_scoped_to_the_complete_event_selection(self):
        from src.contracts.events import parse_notification_event

        descriptor = policy_descriptor()
        second = copy.deepcopy(descriptor["policies"][0])
        second.update({
            "id": "customer-success",
            "connectionId": "mail-secondary",
            "recipientSets": [{
                "id": "customer-success",
                "version": 2,
                "members": [{"id": "secondary"}],
            }],
        })
        descriptor["policies"].append(second)
        resolver, registry, s3 = self.resolver(descriptor=descriptor)
        first_event = self.event()
        second_raw = notification_event()
        second_raw["data"].update({
            "notificationPolicyId": "customer-success",
            "recipientSetId": "customer-success",
            "recipientSetVersion": 2,
            "recipientMemberId": "secondary",
        })
        second_event = parse_notification_event(second_raw)

        first = resolver.resolve(first_event)
        second_result = resolver.resolve(second_event)
        first_replay = resolver.resolve(first_event)

        self.assertEqual(first.policy_id, "billing-ops")
        self.assertEqual(second_result.policy_id, "customer-success")
        self.assertEqual(second_result.connection_id, "mail-secondary")
        self.assertEqual(first_replay, first)
        self.assertEqual(len(registry.calls), 3, "scope metadata must be fresh for each delivery")
        self.assertEqual(len(s3.calls), 4, "each immutable selection is loaded once")

    def test_requires_exact_manifest_path_kind_and_hash(self):
        from src.common.published_policy import PolicyResolutionError

        valid = package_objects()
        manifest_key = f"sites/{SCOPE['domain']}/versions/version-1/_manifest.json"
        manifest = json.loads(valid[manifest_key])
        invalid_objects = []
        changed = copy.deepcopy(valid)
        bad = copy.deepcopy(manifest)
        bad["version"] = True
        changed[manifest_key] = canonical_bytes(bad)
        invalid_objects.append(changed)
        for field, value in (
            ("domain", "other.example.test"),
            ("environment", "production"),
            ("versionId", "other-version"),
        ):
            changed = copy.deepcopy(valid)
            bad = copy.deepcopy(manifest)
            bad[field] = value
            changed[manifest_key] = canonical_bytes(bad)
            invalid_objects.append(changed)
        for field, value in (
            ("path", "other/server/notification-policies.json"),
            ("kind", "server-commerce"),
            ("sha256", "0" * 64),
        ):
            changed = copy.deepcopy(valid)
            bad = copy.deepcopy(manifest)
            bad["files"][0][field] = value
            changed[manifest_key] = canonical_bytes(bad)
            invalid_objects.append(changed)
        changed = copy.deepcopy(valid)
        policy_key = f"sites/{SCOPE['domain']}/versions/version-1/{SCOPE['domain']}/server/notification-policies.json"
        changed[policy_key] = canonical_bytes({"tampered": True})
        invalid_objects.append(changed)

        for objects in invalid_objects:
            with self.subTest(objects=objects), self.assertRaises(PolicyResolutionError):
                self.resolver(objects=objects)[0].resolve(self.event())

    def test_validates_complete_policy_and_recipient_tuple(self):
        from src.common.published_policy import PolicyResolutionError

        base = policy_descriptor()
        invalid = []
        changed = copy.deepcopy(base)
        changed["version"] = True
        invalid.append(changed)
        paths = (
            ("status", "disabled"),
            ("provider", "other"),
            ("id", "other-policy"),
            ("connectionId", "BAD CONNECTION"),
        )
        for key, value in paths:
            changed = copy.deepcopy(base)
            changed["policies"][0][key] = value
            invalid.append(changed)
        changed = copy.deepcopy(base)
        changed["policies"][0]["notificationTypes"] = ["payment-succeeded"]
        changed["policies"][0]["templateIds"] = ["payment-failed-v1"]
        invalid.append(changed)
        changed = copy.deepcopy(base)
        changed["policies"][0]["recipientSets"][0]["version"] = 2
        invalid.append(changed)
        changed = copy.deepcopy(base)
        changed["policies"][0]["recipientSets"][0]["members"][0]["id"] = "other"
        invalid.append(changed)
        changed = copy.deepcopy(base)
        changed["policies"][0]["retryPolicy"]["maxAttempts"] = 6
        invalid.append(changed)
        changed = copy.deepcopy(base)
        changed["policies"][0]["recipientSets"].append({
            "id": "second-set",
            "version": 1,
            "members": [{"id": "primary"}],
        })
        invalid.append(changed)

        for descriptor in invalid:
            with self.subTest(descriptor=descriptor), self.assertRaises(PolicyResolutionError):
                self.resolver(descriptor=descriptor)[0].resolve(self.event())

    def test_rejects_cross_scope_metadata_before_s3(self):
        from src.common.published_policy import PolicyResolutionError

        for mutation in (
            {"domain": "other.example.test"},
            {"serverScope": {"tenantId": "tenant-other", "draftId": SCOPE["draftId"]}},
            {"serverScope": {"tenantId": SCOPE["tenantId"], "draftId": "draft-other"}},
        ):
            registry = FakeRegistry()
            registry.item.update(mutation)
            resolver, _registry, s3 = self.resolver(registry=registry)
            with self.subTest(mutation=mutation), self.assertRaises(PolicyResolutionError):
                resolver.resolve(self.event())
            self.assertEqual(s3.calls, [])

    def test_production_requires_transport_approval(self):
        from src.common.published_policy import PolicyResolutionError, PublishedPolicyResolver
        from src.contracts.events import parse_notification_event

        raw_event = notification_event(environment="production", domain="draft.example.com")
        raw_event["data"]["publishedVersionId"] = "version-prod"
        descriptor = policy_descriptor()
        descriptor["scope"] = {
            "environment": "production",
            "tenantId": SCOPE["tenantId"],
            "draftId": SCOPE["draftId"],
            "domain": "draft.example.com",
        }
        path = "draft.example.com/server/notification-policies.json"
        raw = canonical_bytes(descriptor)
        prefix = "sites/draft.example.com/versions/version-prod/"
        objects = {
            f"{prefix}_manifest.json": canonical_bytes({
                "version": 1,
                "domain": "draft.example.com",
                "environment": "production",
                "versionId": "version-prod",
                "files": [{
                    "path": path,
                    "kind": "server-notification-policies",
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }],
            }),
            f"{prefix}{path}": raw,
        }
        registry = FakeRegistry({
            "pk": "SITE#draft.example.com",
            "sk": "METADATA",
            "domain": "draft.example.com",
            "serverScope": {"tenantId": SCOPE["tenantId"], "draftId": SCOPE["draftId"]},
        })
        resolver = PublishedPolicyResolver(registry, FakeS3(objects), "bucket")

        with self.assertRaises(PolicyResolutionError):
            resolver.resolve(parse_notification_event(raw_event))

        descriptor["policies"][0]["transportApprovalId"] = "approval-1"
        raw = canonical_bytes(descriptor)
        objects[f"{prefix}{path}"] = raw
        manifest = json.loads(objects[f"{prefix}_manifest.json"])
        manifest["files"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
        objects[f"{prefix}_manifest.json"] = canonical_bytes(manifest)
        resolved = PublishedPolicyResolver(registry, FakeS3(objects), "bucket").resolve(
            parse_notification_event(raw_event)
        )
        self.assertEqual(resolved.transport_approval_id, "approval-1")


if __name__ == "__main__":
    unittest.main()
