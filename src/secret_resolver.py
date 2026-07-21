"""Exact Secrets Manager lifecycle and value boundary."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any

try:
    from common.email_address import is_valid_mailbox
    from contracts.events import NotificationEvent
    from integrations_gateway import SMTPConnection
except ModuleNotFoundError:
    from src.common.email_address import is_valid_mailbox
    from src.contracts.events import NotificationEvent
    from src.integrations_gateway import SMTPConnection


_ISOLATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}", re.ASCII)


class SecretResolutionError(RuntimeError):
    """Safe secret lifecycle/value error that never contains secret material."""

    def __init__(self, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


class _DuplicateKey(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SMTPCredentials:
    username: str
    password: str


@dataclass(frozen=True, slots=True)
class Recipient:
    address: str


class SecretResolver:
    def __init__(self, client: Any):
        if client is None:
            raise SecretResolutionError("secret service is unavailable")
        self._client = client

    def smtp(self, event: NotificationEvent, connection: SMTPConnection) -> SMTPCredentials:
        if type(event) is not NotificationEvent or type(connection) is not SMTPConnection:
            raise SecretResolutionError("SMTP secret is invalid")
        expected_path = (
            f"/zoolanding/{event.environment}/{event.tenant_id}/{event.draft_id}/"
            f"notifications/smtp/{connection.connection_id}"
        )
        if connection.credential_reference != expected_path:
            raise SecretResolutionError("SMTP secret scope does not match")
        expected_tags = {
            **_scope_tags(event),
            "zoolanding:secret-purpose": "smtp",
            "zoolanding:connection-id": connection.connection_id,
        }
        value = self._read(
            expected_path,
            expected_tags,
            required_tag_patterns={
                "zoolanding:smtp-account-isolation-id": _ISOLATION_ID,
                "zoolanding:smtp-credential-isolation-id": _ISOLATION_ID,
            },
        )
        if not isinstance(value, dict) or set(value) != {"version", "username", "password"} or type(value.get("version")) is not int or value.get("version") != 1:
            raise SecretResolutionError("SMTP secret value is invalid")
        username = value.get("username")
        password = value.get("password")
        if not _secret_text(username, 256) or not _secret_text(password, 1024):
            raise SecretResolutionError("SMTP secret value is invalid")
        return SMTPCredentials(username, password)

    def recipient(self, event: NotificationEvent) -> Recipient:
        if type(event) is not NotificationEvent:
            raise SecretResolutionError("recipient secret is invalid")
        path = (
            f"/zoolanding/{event.environment}/{event.tenant_id}/{event.draft_id}/"
            f"notifications/recipients/{event.recipient_set_id}/"
            f"{event.recipient_set_version}/{event.recipient_member_id}"
        )
        expected_tags = {
            **_scope_tags(event),
            "zoolanding:secret-purpose": "recipient",
            "zoolanding:recipient-set-id": event.recipient_set_id,
            "zoolanding:recipient-set-version": str(event.recipient_set_version),
            "zoolanding:recipient-member-id": event.recipient_member_id,
        }
        value = self._read(path, expected_tags)
        if not isinstance(value, dict) or set(value) != {"version", "address"} or type(value.get("version")) is not int or value.get("version") != 1:
            raise SecretResolutionError("recipient secret value is invalid")
        address = value.get("address")
        if not is_valid_mailbox(address):
            raise SecretResolutionError("recipient secret value is invalid")
        return Recipient(address)

    def _read(
        self,
        path: str,
        expected_tags: dict[str, str],
        *,
        required_tag_patterns: dict[str, re.Pattern[str]] | None = None,
    ) -> dict[str, Any]:
        try:
            metadata = self._client.describe_secret(SecretId=path)
        except Exception:
            raise SecretResolutionError("secret metadata is unavailable", retryable=True) from None
        if not isinstance(metadata, dict) or metadata.get("Name") != path or metadata.get("DeletedDate") is not None:
            raise SecretResolutionError("secret lifecycle is invalid")
        raw_tags = metadata.get("Tags")
        if not isinstance(raw_tags, list):
            raise SecretResolutionError("secret lifecycle is invalid")
        tags: dict[str, str] = {}
        for tag in raw_tags:
            if (
                not isinstance(tag, dict)
                or set(tag) != {"Key", "Value"}
                or type(tag.get("Key")) is not str
                or type(tag.get("Value")) is not str
                or tag["Key"] in tags
            ):
                raise SecretResolutionError("secret lifecycle is invalid")
            tags[tag["Key"]] = tag["Value"]
        if tags.get("zoolanding:enabled") != "true" or any(tags.get(key) != value for key, value in expected_tags.items()):
            raise SecretResolutionError("secret lifecycle is invalid")
        if any(
            type(tags.get(key)) is not str or pattern.fullmatch(tags[key]) is None
            for key, pattern in (required_tag_patterns or {}).items()
        ):
            raise SecretResolutionError("secret lifecycle is invalid")
        try:
            response = self._client.get_secret_value(SecretId=path)
        except Exception:
            raise SecretResolutionError("secret value is unavailable", retryable=True) from None
        if not isinstance(response, dict) or set(response).intersection({"SecretString", "SecretBinary"}) != {"SecretString"}:
            raise SecretResolutionError("secret value is invalid")
        raw = response["SecretString"]
        if type(raw) is not str or not 2 <= len(raw.encode("utf-8")) <= 8 * 1024:
            raise SecretResolutionError("secret value is invalid")
        try:
            value = json.loads(
                raw,
                object_pairs_hook=_unique_object,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            )
        except (UnicodeError, ValueError, TypeError, RecursionError):
            raise SecretResolutionError("secret value is invalid") from None
        if not isinstance(value, dict):
            raise SecretResolutionError("secret value is invalid")
        return value


def _scope_tags(event: NotificationEvent) -> dict[str, str]:
    return {
        "zoolanding:environment": event.environment,
        "zoolanding:tenant-id": event.tenant_id,
        "zoolanding:draft-id": event.draft_id,
    }


def _secret_text(value: object, maximum: int) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= maximum
        and all(32 <= ord(character) <= 126 for character in value)
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey()
        result[key] = value
    return result
