"""Idempotent delivery ledger, bounded rate buckets, and SMTP circuit state."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from decimal import Decimal
import re
from typing import Any

try:
    from common.published_policy import ResolvedNotificationPolicy
    from contracts.events import NotificationEvent
except ModuleNotFoundError:
    from src.common.published_policy import ResolvedNotificationPolicy
    from src.contracts.events import NotificationEvent


TECHNICAL_TTL_SECONDS = 90 * 24 * 60 * 60
SENDING_LEASE_SECONDS = 45
DRAFT_PER_MINUTE = 20
CONNECTIONS_PER_MINUTE = 100
_SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}", re.ASCII)
_NAMESPACE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}", re.ASCII)
_STATES = {"prepared", "sending", "accepted_by_smtp", "uncertain", "failed"}
_ACCEPTED_REASONS = {"smtp_accepted", "operator_confirmed_acceptance"}
_UNCERTAIN_REASONS = {"smtp_ambiguous", "stale_sending_lease"}
_FAILED_REASONS = {
    "smtp_permanent",
    "smtp_authentication",
    "smtp_quota",
    "retry_exhausted",
    "secret_invalid",
    "circuit_open",
}
_DYNAMODB_INTEGER_MIN = -(2**63)
_DYNAMODB_INTEGER_MAX = 2**63 - 1
_DYNAMODB_NUMERIC_FIELDS = {
    "NotificationDelivery": {
        "recipientSetVersion",
        "attempts",
        "maxAttempts",
        "revision",
        "createdAt",
        "updatedAt",
        "expiresAt",
        "leaseExpiresAt",
        "acceptedAt",
        "uncertainAt",
        "failedAt",
    },
    "NotificationCircuit": {"openedAt", "expiresAt"},
    "NotificationRateBucket": {"bucketMinute", "expiresAt", "count"},
    "NotificationConnectionRateBucket": {"bucketMinute", "expiresAt", "count"},
}


class DeliveryConflict(RuntimeError):
    pass


class RateLimitExceeded(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ClaimResult:
    record: dict[str, Any]
    acquired: bool


class DeliveryStore:
    def __init__(self, backend: Any):
        required = {"get", "put_if_absent", "compare_and_set", "increment_below", "put"}
        if backend is None or any(not callable(getattr(backend, name, None)) for name in required):
            raise DeliveryConflict("delivery store is unavailable")
        self._backend = backend

    def prepare(
        self,
        event: NotificationEvent,
        policy: ResolvedNotificationPolicy,
        *,
        now_epoch: int,
    ) -> dict[str, Any]:
        _inputs(event, now_epoch)
        if type(policy) is not ResolvedNotificationPolicy or not _policy_matches(policy, event):
            raise DeliveryConflict("delivery policy does not match")
        pk, sk = _delivery_key(event)
        item = {
            "pk": pk,
            "sk": sk,
            "itemType": "NotificationDelivery",
            **event.scope,
            "eventId": event.event_id,
            "eventHash": event.event_hash,
            "dedupeKey": event.dedupe_key,
            "publishedVersionId": event.published_version_id,
            "notificationPolicyId": event.notification_policy_id,
            "notificationType": event.notification_type,
            "templateId": event.template_id,
            "recipientSetId": event.recipient_set_id,
            "recipientSetVersion": event.recipient_set_version,
            "recipientMemberId": event.recipient_member_id,
            "sourceType": event.source_type,
            "sourceId": event.source_id,
            "connectionId": policy.connection_id,
            "maxAttempts": policy.max_attempts,
            "state": "prepared",
            "attempts": 0,
            "revision": 1,
            "createdAt": now_epoch,
            "updatedAt": now_epoch,
            "expiresAt": now_epoch + TECHNICAL_TTL_SECONDS,
        }
        if self._backend.put_if_absent(item):
            return copy.deepcopy(item)
        existing = self.get(event)
        if (
            existing["eventHash"] != event.event_hash
            or existing["connectionId"] != policy.connection_id
            or existing["maxAttempts"] != policy.max_attempts
        ):
            raise DeliveryConflict("delivery dedupe collision")
        return existing

    def get(self, event: NotificationEvent) -> dict[str, Any]:
        if type(event) is not NotificationEvent:
            raise DeliveryConflict("delivery key is invalid")
        item = self._backend.get(*_delivery_key(event))
        return _validated_delivery(item, event)

    def claim(
        self,
        event: NotificationEvent,
        *,
        max_attempts: int,
        now_epoch: int,
    ) -> ClaimResult:
        _inputs(event, now_epoch)
        if type(max_attempts) is not int or not 1 <= max_attempts <= 5:
            raise DeliveryConflict("delivery attempt policy is invalid")
        for _ in range(4):
            item = self.get(event)
            if item["maxAttempts"] != max_attempts:
                raise DeliveryConflict("delivery attempt policy does not match")
            if item["state"] == "sending":
                if now_epoch < item["leaseExpiresAt"]:
                    return ClaimResult(item, False)
                if self._cas(
                    item,
                    {"state": "uncertain", "reasonCode": "stale_sending_lease", "uncertainAt": now_epoch, "updatedAt": now_epoch},
                    remove=("leaseExpiresAt",),
                ):
                    return ClaimResult(self.get(event), False)
                continue
            if item["state"] != "prepared":
                return ClaimResult(item, False)
            if item["attempts"] >= max_attempts:
                if self._cas(
                    item,
                    {"state": "failed", "reasonCode": "retry_exhausted", "failedAt": now_epoch, "updatedAt": now_epoch},
                ):
                    return ClaimResult(self.get(event), False)
                continue
            if self._cas(
                item,
                {
                    "state": "sending",
                    "attempts": item["attempts"] + 1,
                    "leaseExpiresAt": now_epoch + SENDING_LEASE_SECONDS,
                    "updatedAt": now_epoch,
                },
                remove=("reasonCode",),
            ):
                return ClaimResult(self.get(event), True)
        raise DeliveryConflict("delivery claim conflicted")

    def mark_accepted(self, event: NotificationEvent, *, now_epoch: int) -> dict[str, Any]:
        return self._transition(
            event,
            "sending",
            {"state": "accepted_by_smtp", "reasonCode": "smtp_accepted", "acceptedAt": now_epoch, "updatedAt": now_epoch},
            now_epoch,
            remove=("leaseExpiresAt",),
        )

    def mark_uncertain(
        self, event: NotificationEvent, reason_code: str, *, now_epoch: int
    ) -> dict[str, Any]:
        if reason_code not in {"smtp_ambiguous", "stale_sending_lease"}:
            raise DeliveryConflict("delivery reason is invalid")
        return self._transition(
            event,
            "sending",
            {"state": "uncertain", "reasonCode": reason_code, "uncertainAt": now_epoch, "updatedAt": now_epoch},
            now_epoch,
            remove=("leaseExpiresAt",),
        )

    def mark_retryable(
        self, event: NotificationEvent, *, max_attempts: int, now_epoch: int
    ) -> dict[str, Any]:
        item = self.get(event)
        if item["state"] != "sending":
            raise DeliveryConflict("delivery transition conflicted")
        if item["attempts"] >= max_attempts:
            updates = {"state": "failed", "reasonCode": "retry_exhausted", "failedAt": now_epoch, "updatedAt": now_epoch}
        else:
            updates = {"state": "prepared", "updatedAt": now_epoch}
        remove = ("leaseExpiresAt", "reasonCode") if updates["state"] == "prepared" else ("leaseExpiresAt",)
        if not self._cas(item, updates, remove=remove):
            raise DeliveryConflict("delivery transition conflicted")
        return self.get(event)

    def mark_failed(
        self, event: NotificationEvent, reason_code: str, *, now_epoch: int
    ) -> dict[str, Any]:
        if reason_code not in _FAILED_REASONS:
            raise DeliveryConflict("delivery reason is invalid")
        item = self.get(event)
        if item["state"] not in {"prepared", "sending"}:
            return item
        if not self._cas(
            item,
            {"state": "failed", "reasonCode": reason_code, "failedAt": now_epoch, "updatedAt": now_epoch},
            remove=("leaseExpiresAt",),
        ):
            raise DeliveryConflict("delivery transition conflicted")
        return self.get(event)

    def reserve_rate(
        self, event: NotificationEvent, namespace: str, *, now_epoch: int
    ) -> None:
        _inputs(event, now_epoch)
        if type(namespace) is not str or _NAMESPACE.fullmatch(namespace) is None:
            raise RateLimitExceeded("notification rate namespace is invalid")
        minute = now_epoch // 60
        expires_at = now_epoch + TECHNICAL_TTL_SECONDS
        draft_item = {
            "pk": f"ENV#{event.environment}#TENANT#{event.tenant_id}#DRAFT#{event.draft_id}#RATE#{minute}",
            "sk": "DRAFT",
            "itemType": "NotificationRateBucket",
            **event.scope,
            "bucketMinute": minute,
            "expiresAt": expires_at,
        }
        connection_item = {
            "pk": f"ENV#{event.environment}#CONNECTION_RATE#{minute}",
            "sk": f"NAMESPACE#{namespace}",
            "itemType": "NotificationConnectionRateBucket",
            "environment": event.environment,
            "rateCircuitNamespace": namespace,
            "bucketMinute": minute,
            "expiresAt": expires_at,
        }
        if not self._backend.increment_below(draft_item, DRAFT_PER_MINUTE):
            raise RateLimitExceeded("draft notification rate is limited")
        if not self._backend.increment_below(connection_item, CONNECTIONS_PER_MINUTE):
            raise RateLimitExceeded("connection notification rate is limited")

    def circuit_open(self, event: NotificationEvent, namespace: str) -> bool:
        if type(event) is not NotificationEvent or type(namespace) is not str or _NAMESPACE.fullmatch(namespace) is None:
            raise DeliveryConflict("notification circuit key is invalid")
        value = self._backend.get(*_circuit_key(event, namespace))
        if value is None:
            return False
        valid = (
            isinstance(value, dict)
            and value.get("itemType") == "NotificationCircuit"
            and value.get("state") == "open"
            and value.get("environment") == event.environment
            and value.get("tenantId") == event.tenant_id
            and value.get("draftId") == event.draft_id
            and value.get("rateCircuitNamespace") == namespace
            and value.get("reasonCode") in {"smtp_authentication", "smtp_quota"}
            and type(value.get("openedAt")) is int
            and type(value.get("expiresAt")) is int
            and 0 <= value["openedAt"] <= value["expiresAt"]
            and value["expiresAt"] == value["openedAt"] + TECHNICAL_TTL_SECONDS
        )
        if not valid:
            raise DeliveryConflict("notification circuit record is invalid")
        return True

    def open_circuit(
        self,
        event: NotificationEvent,
        namespace: str,
        reason_code: str,
        *,
        now_epoch: int,
    ) -> dict[str, Any]:
        _inputs(event, now_epoch)
        if type(namespace) is not str or _NAMESPACE.fullmatch(namespace) is None or reason_code not in {"smtp_authentication", "smtp_quota"}:
            raise DeliveryConflict("notification circuit is invalid")
        pk, sk = _circuit_key(event, namespace)
        item = {
            "pk": pk,
            "sk": sk,
            "itemType": "NotificationCircuit",
            "environment": event.environment,
            "tenantId": event.tenant_id,
            "draftId": event.draft_id,
            "rateCircuitNamespace": namespace,
            "state": "open",
            "reasonCode": reason_code,
            "openedAt": now_epoch,
            "expiresAt": now_epoch + TECHNICAL_TTL_SECONDS,
        }
        self._backend.put(item)
        return copy.deepcopy(item)

    def _transition(self, event, expected_state, updates, now_epoch, *, remove=()):
        _inputs(event, now_epoch)
        item = self.get(event)
        if item["state"] != expected_state or not self._cas(item, updates, remove=remove):
            raise DeliveryConflict("delivery transition conflicted")
        return self.get(event)

    def _cas(self, item, updates, *, remove=()):
        return self._backend.compare_and_set(
            item["pk"], item["sk"], item["revision"], item["state"], updates, remove
        )


class DynamoDeliveryBackend:
    """Small DynamoDB adapter; no scans, queries, or cross-domain reads."""

    def __init__(self, table: Any):
        self._table = table

    def get(self, pk: str, sk: str):
        try:
            item = self._table.get_item(
                Key={"pk": pk, "sk": sk}, ConsistentRead=True
            ).get("Item")
        except Exception:
            raise DeliveryConflict("delivery storage is unavailable") from None
        return _normalize_dynamodb_item(item)

    def put_if_absent(self, item: dict[str, Any]) -> bool:
        try:
            self._table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(#pk) AND attribute_not_exists(#sk)",
                ExpressionAttributeNames={"#pk": "pk", "#sk": "sk"},
            )
            return True
        except Exception as error:
            if _conditional(error):
                return False
            raise DeliveryConflict("delivery storage is unavailable") from None

    def compare_and_set(self, pk, sk, expected_revision, expected_state, updates, remove=()):
        names = {"#revision": "revision", "#state": "state"}
        values = {":expected_revision": expected_revision, ":expected_state": expected_state, ":next_revision": expected_revision + 1}
        sets = ["#revision = :next_revision"]
        for index, (key, value) in enumerate(updates.items()):
            names[f"#u{index}"] = key
            values[f":u{index}"] = value
            sets.append(f"#u{index} = :u{index}")
        removes = []
        for index, key in enumerate(remove):
            names[f"#r{index}"] = key
            removes.append(f"#r{index}")
        expression = "SET " + ", ".join(sets)
        if removes:
            expression += " REMOVE " + ", ".join(removes)
        try:
            self._table.update_item(
                Key={"pk": pk, "sk": sk},
                UpdateExpression=expression,
                ConditionExpression="#revision = :expected_revision AND #state = :expected_state",
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
            )
            return True
        except Exception as error:
            if _conditional(error):
                return False
            raise DeliveryConflict("delivery storage is unavailable") from None

    def increment_below(self, item, limit):
        names = {"#count": "count"}
        values = {":one": 1, ":limit": limit}
        assignments = []
        for index, (key, value) in enumerate(item.items()):
            if key in {"pk", "sk"}:
                continue
            names[f"#f{index}"] = key
            values[f":f{index}"] = value
            assignments.append(f"#f{index} = if_not_exists(#f{index}, :f{index})")
        try:
            self._table.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression="SET " + ", ".join(assignments) + " ADD #count :one",
                ConditionExpression="attribute_not_exists(#count) OR #count < :limit",
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
            )
            return True
        except Exception as error:
            if _conditional(error):
                return False
            raise DeliveryConflict("delivery storage is unavailable") from None

    def put(self, item):
        try:
            self._table.put_item(Item=item)
        except Exception:
            raise DeliveryConflict("delivery storage is unavailable") from None


def _delivery_key(event: NotificationEvent) -> tuple[str, str]:
    return (
        f"ENV#{event.environment}#TENANT#{event.tenant_id}#DRAFT#{event.draft_id}",
        f"DELIVERY#{event.dedupe_key}",
    )


def _circuit_key(event: NotificationEvent, namespace: str) -> tuple[str, str]:
    return (
        f"ENV#{event.environment}#TENANT#{event.tenant_id}#DRAFT#{event.draft_id}",
        f"CIRCUIT#{namespace}",
    )


def _inputs(event: NotificationEvent, now_epoch: int) -> None:
    if type(event) is not NotificationEvent or type(now_epoch) is not int or not 0 <= now_epoch <= 9_999_999_999 - TECHNICAL_TTL_SECONDS:
        raise DeliveryConflict("delivery input is invalid")


def _policy_matches(policy: ResolvedNotificationPolicy, event: NotificationEvent) -> bool:
    return (
        policy.environment == event.environment
        and policy.tenant_id == event.tenant_id
        and policy.draft_id == event.draft_id
        and policy.domain == event.domain
        and policy.version_id == event.published_version_id
        and policy.policy_id == event.notification_policy_id
        and policy.notification_type == event.notification_type
        and policy.template_id == event.template_id
        and policy.recipient_set_id == event.recipient_set_id
        and policy.recipient_set_version == event.recipient_set_version
        and policy.recipient_member_id == event.recipient_member_id
    )


def _validated_delivery(item: object, event: NotificationEvent) -> dict[str, Any]:
    base = {
        "pk", "sk", "itemType", "environment", "tenantId", "draftId", "domain",
        "eventId", "eventHash", "dedupeKey", "publishedVersionId", "notificationPolicyId",
        "notificationType", "templateId", "recipientSetId", "recipientSetVersion",
        "recipientMemberId", "sourceType", "sourceId", "connectionId", "state", "attempts",
        "maxAttempts", "revision", "createdAt", "updatedAt", "expiresAt",
    }
    if isinstance(item, dict) and "reconciliationApprovalId" in item:
        base.add("reconciliationApprovalId")
    if not isinstance(item, dict) or not base.issubset(item) or item.get("state") not in _STATES:
        raise DeliveryConflict("delivery record is invalid")
    allowed = set(base)
    state = item["state"]
    if state == "sending":
        allowed.add("leaseExpiresAt")
    elif state == "accepted_by_smtp":
        allowed.update({"acceptedAt", "reasonCode"})
    elif state == "uncertain":
        allowed.update({"uncertainAt", "reasonCode"})
    elif state == "failed":
        allowed.update({"failedAt", "reasonCode"})
    if set(item) != allowed:
        raise DeliveryConflict("delivery record is invalid")
    pk, sk = _delivery_key(event)
    event_fields = {
        "eventHash": event.event_hash,
        "publishedVersionId": event.published_version_id,
        "notificationPolicyId": event.notification_policy_id,
        "notificationType": event.notification_type,
        "templateId": event.template_id,
        "recipientSetId": event.recipient_set_id,
        "recipientSetVersion": event.recipient_set_version,
        "recipientMemberId": event.recipient_member_id,
        "sourceType": event.source_type,
        "sourceId": event.source_id,
    }
    created_at = item.get("createdAt")
    updated_at = item.get("updatedAt")
    expires_at = item.get("expiresAt")
    if (
        item.get("pk") != pk
        or item.get("sk") != sk
        or item.get("itemType") != "NotificationDelivery"
        or any(item.get(key) != value for key, value in event.scope.items())
        or item.get("eventId") != event.event_id
        or item.get("dedupeKey") != event.dedupe_key
        or any(item.get(key) != value for key, value in event_fields.items())
        or type(item.get("connectionId")) is not str
        or _SAFE_ID.fullmatch(item["connectionId"]) is None
        or type(item.get("attempts")) is not int
        or not 0 <= item["attempts"] <= 5
        or type(item.get("maxAttempts")) is not int
        or not 1 <= item["maxAttempts"] <= 5
        or item["attempts"] > item["maxAttempts"]
        or type(item.get("revision")) is not int
        or item["revision"] < 1
        or any(type(value) is not int for value in (created_at, updated_at, expires_at))
        or not 0 <= created_at <= updated_at <= expires_at
        or expires_at != created_at + TECHNICAL_TTL_SECONDS
        or (
            "reconciliationApprovalId" in item
            and (
                type(item["reconciliationApprovalId"]) is not str
                or _SAFE_ID.fullmatch(item["reconciliationApprovalId"]) is None
            )
        )
    ):
        raise DeliveryConflict("delivery record is invalid")
    if state == "sending" and (
        type(item.get("leaseExpiresAt")) is not int
        or item["leaseExpiresAt"] != updated_at + SENDING_LEASE_SECONDS
    ):
        raise DeliveryConflict("delivery record is invalid")
    terminal = {
        "accepted_by_smtp": ("acceptedAt", _ACCEPTED_REASONS),
        "uncertain": ("uncertainAt", _UNCERTAIN_REASONS),
        "failed": ("failedAt", _FAILED_REASONS),
    }
    if state in terminal:
        timestamp_field, reasons = terminal[state]
        if item.get("reasonCode") not in reasons or item.get(timestamp_field) != updated_at:
            raise DeliveryConflict("delivery record is invalid")
    if (
        state == "accepted_by_smtp"
        and item.get("reasonCode") == "operator_confirmed_acceptance"
        and "reconciliationApprovalId" not in item
    ):
        raise DeliveryConflict("delivery record is invalid")
    return copy.deepcopy(item)


def _normalize_dynamodb_item(item: object):
    """Convert only schema-owned integral DynamoDB numbers to plain integers."""

    if item is None:
        return None
    if not isinstance(item, dict):
        raise DeliveryConflict("delivery storage record is invalid")
    normalized = copy.deepcopy(item)
    numeric_fields = _DYNAMODB_NUMERIC_FIELDS.get(normalized.get("itemType"), set())
    for key, value in normalized.items():
        if key in numeric_fields:
            if type(value) is int:
                if not _DYNAMODB_INTEGER_MIN <= value <= _DYNAMODB_INTEGER_MAX:
                    raise DeliveryConflict("delivery storage number is invalid")
                continue
            if (
                type(value) is not Decimal
                or not value.is_finite()
                or value != value.to_integral_value()
            ):
                raise DeliveryConflict("delivery storage number is invalid")
            integer = int(value)
            if not _DYNAMODB_INTEGER_MIN <= integer <= _DYNAMODB_INTEGER_MAX:
                raise DeliveryConflict("delivery storage number is invalid")
            normalized[key] = integer
        elif _contains_decimal(value):
            raise DeliveryConflict("delivery storage number is not schema-owned")
    return normalized


def _contains_decimal(value: object) -> bool:
    if type(value) is Decimal:
        return True
    if isinstance(value, dict):
        return any(_contains_decimal(key) or _contains_decimal(item) for key, item in value.items())
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_contains_decimal(item) for item in value)
    return False


def _conditional(error: Exception) -> bool:
    response = getattr(error, "response", None)
    return isinstance(response, dict) and response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"
