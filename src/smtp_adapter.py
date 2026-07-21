"""Bounded implicit-TLS SMTP adapter with ambiguity-safe outcomes."""

from __future__ import annotations

from dataclasses import dataclass
from email.message import EmailMessage
import smtplib
import socket
import ssl
from typing import Any, Callable

try:
    from integrations_gateway import SMTPConnection
    from secret_resolver import SMTPCredentials
except (ModuleNotFoundError, ImportError):
    from src.integrations_gateway import SMTPConnection
    from src.secret_resolver import SMTPCredentials


class SMTPConfigurationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SMTPResult:
    outcome: str
    reason_code: str


class SMTPAdapter:
    def __init__(self, factory: Callable[..., Any] = smtplib.SMTP_SSL):
        if not callable(factory):
            raise SMTPConfigurationError("SMTP adapter is unavailable")
        self._factory = factory

    def send(
        self,
        connection: SMTPConnection,
        credentials: SMTPCredentials,
        message: EmailMessage,
    ) -> SMTPResult:
        if (
            type(connection) is not SMTPConnection
            or connection.host != "mail.smtp2go.com"
            or connection.port != 465
            or connection.tls_mode != "implicit"
            or connection.adapter_id != "smtp2go-smtp-v1"
            or type(credentials) is not SMTPCredentials
            or type(message) is not EmailMessage
        ):
            raise SMTPConfigurationError("SMTP adapter configuration is invalid")
        smtp = None
        accepted = False
        try:
            smtp = self._factory(
                "mail.smtp2go.com",
                465,
                timeout=10,
                context=ssl.create_default_context(),
            )
            smtp.login(credentials.username, credentials.password)
            refused = smtp.send_message(
                message,
                from_addr=connection.from_address,
                to_addrs=[str(message["To"])],
            )
            if not isinstance(refused, dict):
                return SMTPResult("uncertain", "smtp_ambiguous")
            if refused:
                return _recipient_result(refused)
            accepted = True
            try:
                smtp.quit()
            except Exception:
                try:
                    smtp.close()
                except Exception:
                    pass
            return SMTPResult("accepted_by_smtp", "smtp_accepted")
        except smtplib.SMTPAuthenticationError as error:
            return _response_result(error.smtp_code)
        except smtplib.SMTPRecipientsRefused as error:
            return _recipient_result(error.recipients)
        except smtplib.SMTPResponseException as error:
            return _response_result(error.smtp_code)
        except (ssl.SSLError, socket.timeout, TimeoutError, smtplib.SMTPServerDisconnected, OSError):
            return SMTPResult("uncertain", "smtp_ambiguous")
        except Exception:
            return SMTPResult("uncertain", "smtp_ambiguous")
        finally:
            if smtp is not None and not accepted:
                try:
                    smtp.close()
                except Exception:
                    pass


def _recipient_result(value: object) -> SMTPResult:
    if not isinstance(value, dict) or not value:
        return SMTPResult("uncertain", "smtp_ambiguous")
    codes: list[int] = []
    for result in value.values():
        if not isinstance(result, (tuple, list)) or not result or type(result[0]) is not int:
            return SMTPResult("uncertain", "smtp_ambiguous")
        codes.append(result[0])
    if 535 in codes:
        return SMTPResult("failed", "smtp_authentication")
    if 552 in codes:
        return SMTPResult("failed", "smtp_quota")
    if any(400 <= code <= 499 for code in codes):
        return SMTPResult("retryable", "smtp_transient")
    if all(500 <= code <= 599 for code in codes):
        return SMTPResult("failed", "smtp_permanent")
    return SMTPResult("uncertain", "smtp_ambiguous")


def _response_result(code: object) -> SMTPResult:
    if code == 535:
        return SMTPResult("failed", "smtp_authentication")
    if code == 552:
        return SMTPResult("failed", "smtp_quota")
    if type(code) is int and 400 <= code <= 499:
        return SMTPResult("retryable", "smtp_transient")
    if type(code) is int and 500 <= code <= 599:
        return SMTPResult("failed", "smtp_permanent")
    return SMTPResult("uncertain", "smtp_ambiguous")
