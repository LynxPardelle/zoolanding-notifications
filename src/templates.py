"""Code-owned plain-text transactional templates."""

from __future__ import annotations

from email.message import EmailMessage
import re

try:
    from common.email_address import is_valid_local_part, is_valid_mailbox
    from contracts.events import NotificationEvent
    from integrations_gateway import SMTPConnection
    from secret_resolver import Recipient
except (ModuleNotFoundError, ImportError):
    from src.common.email_address import is_valid_local_part, is_valid_mailbox
    from src.contracts.events import NotificationEvent
    from src.integrations_gateway import SMTPConnection
    from src.secret_resolver import Recipient


_HEADER_SAFE = re.compile(r"[^\r\n\x00]{1,254}")


class TemplateError(ValueError):
    pass


def render_message(
    event: NotificationEvent,
    connection: SMTPConnection,
    recipient: Recipient,
) -> EmailMessage:
    if type(event) is not NotificationEvent or type(connection) is not SMTPConnection or type(recipient) is not Recipient:
        raise TemplateError("notification template input is invalid")
    expected = {
        "payment-succeeded": "payment-succeeded-v1",
        "payment-failed": "payment-failed-v1",
    }
    if expected.get(event.notification_type) != event.template_id:
        raise TemplateError("notification template is invalid")
    expected_domain = "zoolandingpage.com.mx" if event.environment == "test" else event.domain
    if (
        not is_valid_local_part(connection.from_local_part)
        or connection.from_local_part.lower() != connection.from_local_part
        or not is_valid_local_part(connection.reply_to_local_part)
        or connection.reply_to_local_part.lower() != connection.reply_to_local_part
        or connection.canonical_sending_domain != expected_domain
        or not is_valid_mailbox(connection.from_address)
        or not is_valid_mailbox(connection.reply_to_address)
        or not is_valid_mailbox(recipient.address)
        or any(_HEADER_SAFE.fullmatch(value) is None for value in (
            connection.from_address,
            connection.reply_to_address,
            recipient.address,
        ))
    ):
        raise TemplateError("notification header is invalid")
    amount = f"{event.amount_minor // 100}.{event.amount_minor % 100:02d} {event.currency}"
    if event.notification_type == "payment-succeeded":
        subject = "Pago recibido"
        body = f"Se recibió el pago de la orden {event.order_id} por {amount}."
    else:
        subject = "Cobro no completado"
        body = f"No se completó el cobro de la orden {event.order_id} por {amount}."
    if any(_HEADER_SAFE.fullmatch(value) is None for value in (subject, event.event_id)) or len(body) > 1000:
        raise TemplateError("notification template is invalid")
    message = EmailMessage()
    message["From"] = connection.from_address
    message["Reply-To"] = connection.reply_to_address
    message["To"] = recipient.address
    message["Subject"] = subject
    message["Message-ID"] = f"<{event.event_id}@notifications.{connection.canonical_sending_domain}>"
    message.set_content(body, subtype="plain", charset="utf-8")
    return message
