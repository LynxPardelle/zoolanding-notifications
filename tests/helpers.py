from __future__ import annotations

import hashlib
import json


NOW = 1_800_000_000
SCOPE = {
    "environment": "test",
    "tenantId": "tenant-a",
    "draftId": "draft-a",
    "domain": "draft-a.example.test",
}


def notification_event(**overrides):
    event_id = overrides.pop("eventId", "a" * 64)
    value = {
        "schemaVersion": 1,
        "eventId": event_id,
        "eventType": "notification.requested.v1",
        "occurredAt": NOW,
        **SCOPE,
        "data": {
            "notificationPolicyId": "billing-ops",
            "notificationType": "payment-succeeded",
            "publishedVersionId": "version-1",
            "templateId": "payment-succeeded-v1",
            "recipientSetId": "billing-operators",
            "recipientSetVersion": 1,
            "recipientMemberId": "primary",
            "source": {"type": "commerce-order", "id": "order-1"},
            "dedupeKey": event_id,
            "variables": {
                "orderId": {"type": "safe-id", "value": "order-1"},
                "amountMinor": {"type": "integer", "value": 90_000},
                "currency": {"type": "currency", "value": "MXN"},
            },
        },
    }
    value.update(overrides)
    return value


def policy_descriptor(*, status="active", connection_id="mail-primary"):
    return {
        "version": 1,
        "scope": dict(SCOPE),
        "policies": [
            {
                "id": "billing-ops",
                "status": status,
                "provider": "email.smtp",
                "connectionId": connection_id,
                "notificationTypes": ["payment-succeeded", "payment-failed"],
                "templateIds": ["payment-succeeded-v1", "payment-failed-v1"],
                "recipientSets": [
                    {
                        "id": "billing-operators",
                        "version": 1,
                        "members": [{"id": "primary"}],
                    }
                ],
                "retryPolicy": {"maxAttempts": 5},
                "acceptanceStatus": "accepted_by_smtp",
            }
        ],
    }


def canonical_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def package_objects(descriptor=None):
    descriptor = descriptor or policy_descriptor()
    path = f"{SCOPE['domain']}/server/notification-policies.json"
    prefix = f"sites/{SCOPE['domain']}/versions/version-1/"
    raw = canonical_bytes(descriptor)
    manifest = {
        "version": 1,
        "domain": SCOPE["domain"],
        "environment": SCOPE["environment"],
        "versionId": "version-1",
        "files": [
            {
                "path": path,
                "kind": "server-notification-policies",
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        ],
    }
    return {
        f"{prefix}_manifest.json": canonical_bytes(manifest),
        f"{prefix}{path}": raw,
    }


class Body:
    def __init__(self, value):
        self.value = value

    def read(self, amount=-1):
        return self.value if amount < 0 else self.value[:amount]


class FakeS3:
    def __init__(self, objects):
        self.objects = dict(objects)
        self.calls = []

    def get_object(self, *, Bucket, Key):
        self.calls.append((Bucket, Key))
        raw = self.objects[Key]
        return {"ContentLength": len(raw), "Body": Body(raw)}


class FakeRegistry:
    def __init__(self, item=None):
        self.item = item or {
            "pk": f"SITE#{SCOPE['domain']}",
            "sk": "METADATA",
            "domain": SCOPE["domain"],
            "serverScope": {
                "tenantId": SCOPE["tenantId"],
                "draftId": SCOPE["draftId"],
            },
            "publishedEnvironments": {
                "test": {
                    "versionId": "current-version-that-must-not-be-used",
                    "prefix": "must-not-be-used",
                }
            },
        }
        self.calls = []

    def get_item(self, **kwargs):
        self.calls.append(kwargs)
        return {"Item": dict(self.item)}
