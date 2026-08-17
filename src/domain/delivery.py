"""One-message notification delivery orchestration."""

from __future__ import annotations

from typing import Any

try:
    from contracts.events import NotificationEvent
    from secret_resolver import SecretResolutionError
    from templates import render_message
except (ModuleNotFoundError, ImportError):
    from src.contracts.events import NotificationEvent
    from src.secret_resolver import SecretResolutionError
    from src.templates import render_message


class NotificationWorker:
    def __init__(self, policies: Any, connections: Any, secrets: Any, store: Any, smtp: Any, metrics: Any):
        self._policies = policies
        self._connections = connections
        self._secrets = secrets
        self._store = store
        self._smtp = smtp
        self._metrics = metrics

    def record_test_live_mismatch(self, expected_environment: str) -> None:
        self._metrics.test_live_mismatch(expected_environment)

    def process(self, event: NotificationEvent, *, now_epoch: int) -> str:
        try:
            policy = self._policies.resolve(event)
        except Exception:
            return "retry"
        try:
            record = self._store.prepare(event, policy, now_epoch=now_epoch)
        except Exception:
            return "retry"
        if record["state"] == "accepted_by_smtp":
            return "processed"
        if record["state"] in {"sending", "uncertain", "failed"}:
            if record["state"] == "sending":
                try:
                    claim = self._store.claim(
                        event,
                        max_attempts=policy.max_attempts,
                        now_epoch=now_epoch,
                    )
                except Exception:
                    return "retry"
                record = claim.record
                if record["state"] == "accepted_by_smtp":
                    return "processed"
            return "retry"
        try:
            connection = self._connections.resolve(event, policy)
            if self._store.circuit_open(event, connection.rate_circuit_namespace):
                self._store.mark_failed(event, "circuit_open", now_epoch=now_epoch)
                return "retry"
            self._store.reserve_rate(event, connection.rate_circuit_namespace, now_epoch=now_epoch)
        except Exception:
            return "retry"
        try:
            smtp_credentials = self._secrets.smtp(event, connection)
            recipient = self._secrets.recipient(event)
            message = render_message(event, connection, recipient)
        except SecretResolutionError as error:
            if not error.retryable:
                try:
                    self._store.mark_failed(event, "secret_invalid", now_epoch=now_epoch)
                except Exception:
                    pass
            return "retry"
        except Exception:
            try:
                self._store.mark_failed(event, "secret_invalid", now_epoch=now_epoch)
            except Exception:
                pass
            return "retry"
        try:
            claim = self._store.claim(
                event,
                max_attempts=policy.max_attempts,
                now_epoch=now_epoch,
            )
        except Exception:
            return "retry"
        claimed = claim.record
        if not claim.acquired:
            return "processed" if claimed["state"] == "accepted_by_smtp" else "retry"
        if claimed["state"] != "sending":
            return "retry"
        try:
            result = self._smtp.send(connection, smtp_credentials, message)
        except Exception:
            try:
                self._store.mark_uncertain(event, "smtp_ambiguous", now_epoch=now_epoch)
            except Exception:
                pass
            return "retry"
        try:
            if result.outcome == "accepted_by_smtp" and result.reason_code == "smtp_accepted":
                self._store.mark_accepted(event, now_epoch=now_epoch)
                return "processed"
            if result.outcome == "retryable" and result.reason_code in {"smtp_transient", "smtp_throttled"}:
                self._store.mark_retryable(event, max_attempts=policy.max_attempts, now_epoch=now_epoch)
                if result.reason_code == "smtp_throttled":
                    self._metrics.smtp_throttled(event.environment)
                return "retry"
            if result.outcome == "uncertain" and result.reason_code == "smtp_ambiguous":
                self._store.mark_uncertain(event, result.reason_code, now_epoch=now_epoch)
                return "retry"
            if result.outcome == "failed" and result.reason_code in {"smtp_authentication", "smtp_quota", "smtp_permanent"}:
                self._store.mark_failed(event, result.reason_code, now_epoch=now_epoch)
                if result.reason_code in {"smtp_authentication", "smtp_quota"}:
                    self._store.open_circuit(
                        event,
                        connection.rate_circuit_namespace,
                        result.reason_code,
                        now_epoch=now_epoch,
                    )
                    self._metrics.circuit_opened(event.environment, result.reason_code)
                return "retry"
            self._store.mark_uncertain(event, "smtp_ambiguous", now_epoch=now_epoch)
            return "retry"
        except Exception:
            return "retry"
