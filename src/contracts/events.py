"""Strict provider-neutral notification event contract."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any


_SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}", re.ASCII)
_EVENT_ID = re.compile(r"[a-f0-9]{64}", re.ASCII)
_VERSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", re.ASCII)
_DOMAIN = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
    re.ASCII,
)
_CURRENCY = re.compile(r"[A-Z]{3}", re.ASCII)
_TYPE_TEMPLATE = {
    "payment-succeeded": "payment-succeeded-v1",
    "payment-failed": "payment-failed-v1",
}


class EventContractError(ValueError):
    """Safe fail-closed event validation error."""


class _DuplicateKey(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class NotificationEvent:
    schema_version: int
    event_id: str
    event_type: str
    occurred_at: int
    environment: str
    tenant_id: str
    draft_id: str
    domain: str
    notification_policy_id: str
    notification_type: str
    published_version_id: str
    template_id: str
    recipient_set_id: str
    recipient_set_version: int
    recipient_member_id: str
    source_type: str
    source_id: str
    dedupe_key: str
    order_id: str
    amount_minor: int
    currency: str
    event_hash: str

    @property
    def scope(self) -> dict[str, str]:
        return {
            "environment": self.environment,
            "tenantId": self.tenant_id,
            "draftId": self.draft_id,
            "domain": self.domain,
        }


def parse_event_json(raw: object) -> NotificationEvent:
    if type(raw) is not str:
        raise EventContractError("notification event is invalid")
    try:
        encoded_length = len(raw.encode("utf-8"))
    except UnicodeError:
        raise EventContractError("notification event is invalid") from None
    if not 2 <= encoded_length <= 64 * 1024:
        raise EventContractError("notification event is invalid")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise EventContractError("notification event is invalid") from None
    return parse_notification_event(value)


def parse_notification_event(value: object) -> NotificationEvent:
    envelope = _closed(
        value,
        {
            "schemaVersion",
            "eventId",
            "eventType",
            "occurredAt",
            "environment",
            "tenantId",
            "draftId",
            "domain",
            "data",
        },
    )
    if type(envelope["schemaVersion"]) is not int or envelope["schemaVersion"] != 1 or envelope["eventType"] != "notification.requested.v1":
        raise EventContractError("notification event is invalid")
    event_id = _event_id(envelope["eventId"])
    occurred_at = envelope["occurredAt"]
    if type(occurred_at) is not int or not 0 <= occurred_at <= 9_999_999_999:
        raise EventContractError("notification event is invalid")
    environment = envelope["environment"]
    if environment not in {"test", "production"}:
        raise EventContractError("notification event is invalid")
    tenant_id = _safe_id(envelope["tenantId"])
    draft_id = _safe_id(envelope["draftId"])
    domain = envelope["domain"]
    if type(domain) is not str or not 4 <= len(domain) <= 253 or _DOMAIN.fullmatch(domain) is None:
        raise EventContractError("notification event is invalid")

    data = _closed(
        envelope["data"],
        {
            "notificationPolicyId",
            "notificationType",
            "publishedVersionId",
            "templateId",
            "recipientSetId",
            "recipientSetVersion",
            "recipientMemberId",
            "source",
            "dedupeKey",
            "variables",
        },
    )
    notification_type = data["notificationType"]
    template_id = data["templateId"]
    if _TYPE_TEMPLATE.get(notification_type) != template_id:
        raise EventContractError("notification event is invalid")
    source = _closed(data["source"], {"type", "id"})
    if source["type"] != "commerce-order":
        raise EventContractError("notification event is invalid")
    source_id = _safe_id(source["id"])
    variables = _closed(data["variables"], {"orderId", "amountMinor", "currency"})
    order = _closed(variables["orderId"], {"type", "value"})
    amount = _closed(variables["amountMinor"], {"type", "value"})
    currency = _closed(variables["currency"], {"type", "value"})
    order_id = _safe_id(order["value"])
    amount_minor = amount["value"]
    currency_value = currency["value"]
    if (
        order["type"] != "safe-id"
        or order_id != source_id
        or amount["type"] != "integer"
        or type(amount_minor) is not int
        or not 0 <= amount_minor <= 99_999_999
        or currency["type"] != "currency"
        or type(currency_value) is not str
        or _CURRENCY.fullmatch(currency_value) is None
    ):
        raise EventContractError("notification event is invalid")
    dedupe_key = _event_id(data["dedupeKey"])
    if dedupe_key != event_id:
        raise EventContractError("notification event is invalid")
    recipient_set_version = data["recipientSetVersion"]
    if type(recipient_set_version) is not int or not 1 <= recipient_set_version <= 2_147_483_647:
        raise EventContractError("notification event is invalid")
    try:
        canonical = json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError):
        raise EventContractError("notification event is invalid") from None
    return NotificationEvent(
        1,
        event_id,
        "notification.requested.v1",
        occurred_at,
        environment,
        tenant_id,
        draft_id,
        domain,
        _safe_id(data["notificationPolicyId"]),
        notification_type,
        _version_id(data["publishedVersionId"]),
        template_id,
        _safe_id(data["recipientSetId"]),
        recipient_set_version,
        _safe_id(data["recipientMemberId"]),
        "commerce-order",
        source_id,
        dedupe_key,
        order_id,
        amount_minor,
        currency_value,
        hashlib.sha256(canonical).hexdigest(),
    )


def _closed(value: object, required: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != required:
        raise EventContractError("notification event is invalid")
    return value


def _safe_id(value: object) -> str:
    if type(value) is not str or _SAFE_ID.fullmatch(value) is None:
        raise EventContractError("notification event is invalid")
    return value


def _version_id(value: object) -> str:
    if type(value) is not str or _VERSION_ID.fullmatch(value) is None:
        raise EventContractError("notification event is invalid")
    return value


def _event_id(value: object) -> str:
    if type(value) is not str or _EVENT_ID.fullmatch(value) is None:
        raise EventContractError("notification event is invalid")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise _DuplicateKey()
        output[key] = value
    return output
