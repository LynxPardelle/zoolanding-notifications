"""Resolve one notification policy from an event-pinned immutable package."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any

try:
    from contracts.events import NotificationEvent
except ModuleNotFoundError:
    from src.contracts.events import NotificationEvent


MAX_JSON_BYTES = 256 * 1024
_SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}", re.ASCII)
_HASH = re.compile(r"[a-f0-9]{64}", re.ASCII)
_TYPE_TEMPLATE = {
    "payment-succeeded": "payment-succeeded-v1",
    "payment-failed": "payment-failed-v1",
}


class PolicyResolutionError(RuntimeError):
    """Safe fail-closed immutable policy resolution error."""


class _DuplicateKey(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ResolvedNotificationPolicy:
    environment: str
    tenant_id: str
    draft_id: str
    domain: str
    version_id: str
    policy_id: str
    connection_id: str
    notification_type: str
    template_id: str
    recipient_set_id: str
    recipient_set_version: int
    recipient_member_id: str
    max_attempts: int
    transport_approval_id: str | None


class PublishedPolicyResolver:
    """Refresh Registry scope every call and cache only exact policy selections."""

    def __init__(self, registry_table: Any, s3_client: Any, bucket_name: str):
        if registry_table is None or s3_client is None or type(bucket_name) is not str or not bucket_name:
            raise PolicyResolutionError("published notification policy is unavailable")
        self._registry = registry_table
        self._s3 = s3_client
        self._bucket = bucket_name
        self._cache: dict[tuple[object, ...], ResolvedNotificationPolicy] = {}

    def resolve(self, event: NotificationEvent) -> ResolvedNotificationPolicy:
        if type(event) is not NotificationEvent:
            raise PolicyResolutionError("published notification policy is invalid")
        self._validate_fresh_scope(event)
        cache_key = (
            event.environment,
            event.tenant_id,
            event.draft_id,
            event.domain,
            event.published_version_id,
            event.notification_policy_id,
            event.notification_type,
            event.template_id,
            event.recipient_set_id,
            event.recipient_set_version,
            event.recipient_member_id,
        )
        cached = self._cache.get(cache_key)
        if cached is not None:
            self._validate_tuple(cached, event)
            return cached
        prefix = f"sites/{event.domain}/versions/{event.published_version_id}/"
        manifest = self._load_json(f"{prefix}_manifest.json")
        path = f"{event.domain}/server/notification-policies.json"
        expected_hash = self._manifest_hash(manifest.value, event, path)
        descriptor = self._load_json(f"{prefix}{path}")
        if not hashlib.sha256(descriptor.raw).hexdigest() == expected_hash:
            raise PolicyResolutionError("published notification package is invalid")
        resolved = self._resolve_descriptor(descriptor.value, event)
        self._cache[cache_key] = resolved
        return resolved

    def _validate_fresh_scope(self, event: NotificationEvent) -> None:
        try:
            response = self._registry.get_item(
                Key={"pk": f"SITE#{event.domain}", "sk": "METADATA"},
                ConsistentRead=True,
            )
        except Exception:
            raise PolicyResolutionError("published notification policy is unavailable") from None
        item = response.get("Item") if isinstance(response, dict) else None
        expected_scope = {"tenantId": event.tenant_id, "draftId": event.draft_id}
        if (
            not isinstance(item, dict)
            or item.get("pk") != f"SITE#{event.domain}"
            or item.get("sk") != "METADATA"
            or item.get("domain") != event.domain
            or item.get("serverScope") != expected_scope
        ):
            raise PolicyResolutionError("published notification scope does not match")

    def _manifest_hash(self, manifest: object, event: NotificationEvent, path: str) -> str:
        if (
            not isinstance(manifest, dict)
            or set(manifest) != {"version", "domain", "environment", "versionId", "files"}
            or type(manifest.get("version")) is not int
            or manifest.get("version") != 1
            or manifest.get("domain") != event.domain
            or manifest.get("environment") != event.environment
            or manifest.get("versionId") != event.published_version_id
            or not isinstance(manifest.get("files"), list)
            or not 1 <= len(manifest["files"]) <= 512
        ):
            raise PolicyResolutionError("published notification package is invalid")
        seen: set[str] = set()
        match: list[str] = []
        for entry in manifest["files"]:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"path", "kind", "sha256"}
                or type(entry.get("path")) is not str
                or type(entry.get("kind")) is not str
                or type(entry.get("sha256")) is not str
                or _HASH.fullmatch(entry["sha256"]) is None
                or entry["path"] in seen
            ):
                raise PolicyResolutionError("published notification package is invalid")
            seen.add(entry["path"])
            if entry["path"] == path:
                if entry["kind"] != "server-notification-policies":
                    raise PolicyResolutionError("published notification package is invalid")
                match.append(entry["sha256"])
        if len(match) != 1:
            raise PolicyResolutionError("published notification package is invalid")
        return match[0]

    def _resolve_descriptor(
        self, descriptor: object, event: NotificationEvent
    ) -> ResolvedNotificationPolicy:
        if (
            not isinstance(descriptor, dict)
            or set(descriptor) != {"version", "scope", "policies"}
            or type(descriptor.get("version")) is not int
            or descriptor.get("version") != 1
            or descriptor.get("scope") != event.scope
            or not isinstance(descriptor.get("policies"), list)
            or len(descriptor["policies"]) > 32
        ):
            raise PolicyResolutionError("published notification policy is invalid")
        selected: list[dict[str, Any]] = []
        seen: set[str] = set()
        for value in descriptor["policies"]:
            policy = self._validated_policy(value, event.environment)
            if policy["id"] in seen:
                raise PolicyResolutionError("published notification policy is invalid")
            seen.add(policy["id"])
            if policy["id"] == event.notification_policy_id:
                selected.append(policy)
        if len(selected) != 1 or selected[0]["status"] != "active":
            raise PolicyResolutionError("published notification policy is unavailable")
        policy = selected[0]
        recipient = [
            item
            for item in policy["recipientSets"]
            if item["id"] == event.recipient_set_id
            and item["version"] == event.recipient_set_version
            and item["members"][0]["id"] == event.recipient_member_id
        ]
        if (
            event.notification_type not in policy["notificationTypes"]
            or event.template_id not in policy["templateIds"]
            or len(recipient) != 1
        ):
            raise PolicyResolutionError("published notification tuple is invalid")
        resolved = ResolvedNotificationPolicy(
            event.environment,
            event.tenant_id,
            event.draft_id,
            event.domain,
            event.published_version_id,
            policy["id"],
            policy["connectionId"],
            event.notification_type,
            event.template_id,
            event.recipient_set_id,
            event.recipient_set_version,
            event.recipient_member_id,
            policy["retryPolicy"]["maxAttempts"],
            policy.get("transportApprovalId"),
        )
        self._validate_tuple(resolved, event)
        return resolved

    def _validated_policy(self, value: object, environment: str) -> dict[str, Any]:
        required = {
            "id",
            "status",
            "provider",
            "connectionId",
            "notificationTypes",
            "templateIds",
            "recipientSets",
            "retryPolicy",
            "acceptanceStatus",
        }
        if (
            not isinstance(value, dict)
            or set(value) not in (required, required | {"transportApprovalId"})
            or _safe_id(value.get("id")) is None
            or value.get("status") not in {"disabled", "active"}
            or value.get("provider") != "email.smtp"
            or _safe_id(value.get("connectionId")) is None
            or value.get("acceptanceStatus") != "accepted_by_smtp"
        ):
            raise PolicyResolutionError("published notification policy is invalid")
        types = _unique_allowed(value.get("notificationTypes"), set(_TYPE_TEMPLATE), 32)
        templates = _unique_allowed(value.get("templateIds"), set(_TYPE_TEMPLATE.values()), 32)
        if {_TYPE_TEMPLATE[item] for item in types} != templates:
            raise PolicyResolutionError("published notification policy is invalid")
        recipients = value.get("recipientSets")
        if not isinstance(recipients, list) or len(recipients) != 1:
            raise PolicyResolutionError("published notification policy is invalid")
        recipient_ids: set[tuple[str, int]] = set()
        for recipient in recipients:
            if (
                not isinstance(recipient, dict)
                or set(recipient) != {"id", "version", "members"}
                or _safe_id(recipient.get("id")) is None
                or type(recipient.get("version")) is not int
                or not 1 <= recipient["version"] <= 2_147_483_647
                or not isinstance(recipient.get("members"), list)
                or len(recipient["members"]) != 1
                or not isinstance(recipient["members"][0], dict)
                or set(recipient["members"][0]) != {"id"}
                or _safe_id(recipient["members"][0].get("id")) is None
            ):
                raise PolicyResolutionError("published notification policy is invalid")
            key = (recipient["id"], recipient["version"])
            if key in recipient_ids:
                raise PolicyResolutionError("published notification policy is invalid")
            recipient_ids.add(key)
        retry = value.get("retryPolicy")
        if (
            not isinstance(retry, dict)
            or set(retry) != {"maxAttempts"}
            or type(retry.get("maxAttempts")) is not int
            or not 1 <= retry["maxAttempts"] <= 5
        ):
            raise PolicyResolutionError("published notification policy is invalid")
        approval = value.get("transportApprovalId")
        if approval is not None and _safe_id(approval) is None:
            raise PolicyResolutionError("published notification policy is invalid")
        if environment == "production" and value["status"] == "active" and approval is None:
            raise PolicyResolutionError("published notification policy is invalid")
        return value

    @staticmethod
    def _validate_tuple(policy: ResolvedNotificationPolicy, event: NotificationEvent) -> None:
        if (
            policy.environment != event.environment
            or policy.tenant_id != event.tenant_id
            or policy.draft_id != event.draft_id
            or policy.domain != event.domain
            or policy.version_id != event.published_version_id
            or policy.policy_id != event.notification_policy_id
            or policy.notification_type != event.notification_type
            or policy.template_id != event.template_id
            or policy.recipient_set_id != event.recipient_set_id
            or policy.recipient_set_version != event.recipient_set_version
            or policy.recipient_member_id != event.recipient_member_id
        ):
            raise PolicyResolutionError("published notification tuple is invalid")

    def _load_json(self, key: str) -> _LoadedJson:
        try:
            response = self._s3.get_object(Bucket=self._bucket, Key=key)
            length = response.get("ContentLength")
            if type(length) is not int or not 2 <= length <= MAX_JSON_BYTES:
                raise PolicyResolutionError("published notification package is invalid")
            raw = response["Body"].read(MAX_JSON_BYTES + 1)
        except PolicyResolutionError:
            raise
        except Exception:
            raise PolicyResolutionError("published notification package is unavailable") from None
        if type(raw) is not bytes or len(raw) != length or len(raw) > MAX_JSON_BYTES:
            raise PolicyResolutionError("published notification package is invalid")
        try:
            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            )
        except (UnicodeError, ValueError, TypeError, RecursionError):
            raise PolicyResolutionError("published notification package is invalid") from None
        if not isinstance(value, dict):
            raise PolicyResolutionError("published notification package is invalid")
        return _LoadedJson(raw, value)


@dataclass(frozen=True, slots=True)
class _LoadedJson:
    raw: bytes
    value: dict[str, Any]


def _safe_id(value: object) -> str | None:
    return value if type(value) is str and _SAFE_ID.fullmatch(value) is not None else None


def _unique_allowed(value: object, allowed: set[str], maximum: int) -> set[str]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= maximum
        or any(type(item) is not str or item not in allowed for item in value)
        or len(set(value)) != len(value)
    ):
        raise PolicyResolutionError("published notification policy is invalid")
    return set(value)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise _DuplicateKey()
        output[key] = value
    return output
