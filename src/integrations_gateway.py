"""Closed AWS_IAM connection-resolution client for the SMTP transport."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

try:
    from common.email_address import is_valid_local_part
    from common.published_policy import ResolvedNotificationPolicy
    from contracts.events import NotificationEvent
except ModuleNotFoundError:
    from src.common.email_address import is_valid_local_part
    from src.common.published_policy import ResolvedNotificationPolicy
    from src.contracts.events import NotificationEvent


_NAMESPACE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}", re.ASCII)
_API_ID = re.compile(r"[a-z0-9]{10}", re.ASCII)
_REGION = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-\d", re.ASCII)
_PATH = "/internal/v1/integrations/connection-resolve"


class ConnectionResolutionError(RuntimeError):
    """Safe fail-closed connection-resolution error."""


class _DuplicateKey(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SMTPConnection:
    connection_id: str
    mode: str
    adapter_id: str
    adapter_version: str
    credential_reference: str
    host: str
    port: int
    tls_mode: str
    canonical_sending_domain: str
    from_local_part: str
    reply_to_local_part: str
    rate_circuit_namespace: str

    @property
    def from_address(self) -> str:
        return f"{self.from_local_part}@{self.canonical_sending_domain}"

    @property
    def reply_to_address(self) -> str:
        return f"{self.reply_to_local_part}@{self.canonical_sending_domain}"


class ConnectionResolver:
    def __init__(self, invoke: Callable[[str, dict[str, Any]], object]):
        if not callable(invoke):
            raise ConnectionResolutionError("connection resolver is unavailable")
        self._invoke = invoke

    def resolve(
        self, event: NotificationEvent, policy: ResolvedNotificationPolicy
    ) -> SMTPConnection:
        if type(event) is not NotificationEvent or type(policy) is not ResolvedNotificationPolicy:
            raise ConnectionResolutionError("connection resolution is invalid")
        if (
            policy.environment != event.environment
            or policy.tenant_id != event.tenant_id
            or policy.draft_id != event.draft_id
            or policy.domain != event.domain
            or policy.version_id != event.published_version_id
            or policy.policy_id != event.notification_policy_id
        ):
            raise ConnectionResolutionError("connection resolution scope does not match")
        digest = hashlib.sha256(
            f"{event.event_hash}\0{policy.connection_id}".encode("ascii")
        ).hexdigest()
        command = {
            "version": 1,
            "scope": event.scope,
            "connectionId": policy.connection_id,
            "commandId": f"notification-resolve-{digest[:40]}",
            "idempotencyKey": f"notifications-resolve-v1:{digest}",
            "input": {"provider": "email.smtp", "capability": "send"},
        }
        try:
            value = self._invoke(_PATH, command)
        except Exception:
            raise ConnectionResolutionError("connection resolution is unavailable") from None
        return _validated_resolution(value, event, policy)


def _validated_resolution(
    value: object,
    event: NotificationEvent,
    policy: ResolvedNotificationPolicy,
) -> SMTPConnection:
    required = {
        "connectionId",
        "provider",
        "mode",
        "adapterVersion",
        "adapterId",
        "credentialReference",
        "endpoint",
        "senderPolicy",
        "rateCircuitNamespace",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ConnectionResolutionError("connection resolution is invalid")
    expected_mode = "test" if event.environment == "test" else "live"
    expected_reference = (
        f"/zoolanding/{event.environment}/{event.tenant_id}/{event.draft_id}/"
        f"notifications/smtp/{policy.connection_id}"
    )
    endpoint = value.get("endpoint")
    sender = value.get("senderPolicy")
    expected_domain = "zoolandingpage.com.mx" if event.environment == "test" else event.domain
    if (
        value.get("connectionId") != policy.connection_id
        or value.get("provider") != "email.smtp"
        or value.get("mode") != expected_mode
        or value.get("adapterVersion") != "v1"
        or value.get("adapterId") != "smtp2go-smtp-v1"
        or value.get("credentialReference") != expected_reference
        or not isinstance(endpoint, dict)
        or set(endpoint) != {"host", "port", "tlsMode", "canonicalSendingDomain"}
        or endpoint.get("host") != "mail.smtp2go.com"
        or endpoint.get("port") != 465
        or endpoint.get("tlsMode") != "implicit"
        or endpoint.get("canonicalSendingDomain") != expected_domain
        or not isinstance(sender, dict)
        or set(sender) != {"fromLocalPart", "replyToLocalPart"}
        or type(sender.get("fromLocalPart")) is not str
        or sender["fromLocalPart"].lower() != sender["fromLocalPart"]
        or not is_valid_local_part(sender["fromLocalPart"])
        or type(sender.get("replyToLocalPart")) is not str
        or sender["replyToLocalPart"].lower() != sender["replyToLocalPart"]
        or not is_valid_local_part(sender["replyToLocalPart"])
        or type(value.get("rateCircuitNamespace")) is not str
        or _NAMESPACE.fullmatch(value["rateCircuitNamespace"]) is None
    ):
        raise ConnectionResolutionError("connection resolution is invalid")
    return SMTPConnection(
        policy.connection_id,
        expected_mode,
        "smtp2go-smtp-v1",
        "v1",
        expected_reference,
        "mail.smtp2go.com",
        465,
        "implicit",
        expected_domain,
        sender["fromLocalPart"],
        sender["replyToLocalPart"],
        value["rateCircuitNamespace"],
    )


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


class SignedAWSIAMInvoker:
    """Minimal SigV4 POST invoker with a fixed execute-api origin and path."""

    def __init__(
        self,
        api_id: str,
        environment: str,
        region: str,
        url_suffix: str,
        credentials_provider: Callable[[], Any] | None = None,
        *,
        timeout_seconds: int = 5,
    ):
        if (
            type(api_id) is not str
            or _API_ID.fullmatch(api_id) is None
            or environment not in {"test", "production"}
            or type(region) is not str
            or _REGION.fullmatch(region) is None
            or type(timeout_seconds) is not int
            or not 1 <= timeout_seconds <= 10
        ):
            raise ConnectionResolutionError("connection endpoint is invalid")
        expected_suffix = "amazonaws.com.cn" if region.startswith("cn-") else "amazonaws.com"
        if url_suffix != expected_suffix:
            raise ConnectionResolutionError("connection endpoint is invalid")
        self._base_url = (
            f"https://{api_id}.execute-api.{region}.{url_suffix}/{environment}"
        )
        self._region = region
        self._credentials_provider = credentials_provider
        self._timeout = timeout_seconds
        self._opener = build_opener(_NoRedirect())

    def __call__(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        if path != _PATH:
            raise ConnectionResolutionError("connection path is invalid")
        try:
            from botocore.auth import SigV4Auth
            from botocore.awsrequest import AWSRequest
            import boto3

            body = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
            provider = self._credentials_provider
            credentials = provider() if provider is not None else boto3.Session().get_credentials()
            if credentials is None:
                raise ConnectionResolutionError("connection credentials are unavailable")
            frozen = credentials.get_frozen_credentials() if hasattr(credentials, "get_frozen_credentials") else credentials
            url = self._base_url + path
            aws_request = AWSRequest(
                method="POST",
                url=url,
                data=body,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            SigV4Auth(frozen, "execute-api", self._region).add_auth(aws_request)
            request = Request(url, data=body, method="POST", headers=dict(aws_request.headers))
            with self._opener.open(request, timeout=self._timeout) as response:
                raw = response.read(16 * 1024 + 1)
                status = response.status
        except ConnectionResolutionError:
            raise
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, TypeError):
            raise ConnectionResolutionError("connection resolution is unavailable") from None
        except Exception:
            raise ConnectionResolutionError("connection resolution is unavailable") from None
        if status != 200 or len(raw) > 16 * 1024:
            raise ConnectionResolutionError("connection resolution is unavailable")
        return _decode_json_response(raw)


def _decode_json_response(raw: object) -> dict[str, Any]:
    if type(raw) is not bytes or not 2 <= len(raw) <= 16 * 1024:
        raise ConnectionResolutionError("connection resolution is invalid")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise ConnectionResolutionError("connection resolution is invalid") from None
    if not isinstance(value, dict):
        raise ConnectionResolutionError("connection resolution is invalid")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey()
        result[key] = value
    return result
