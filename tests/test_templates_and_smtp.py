import smtplib
import socket
import ssl
import unittest

from tests.test_integrations_gateway import Invoke, parsed_event, resolution, resolved_policy
from tests.test_secrets import SecretClient


def dependencies():
    from src.integrations_gateway import ConnectionResolver
    from src.secret_resolver import SecretResolver

    event = parsed_event()
    connection = ConnectionResolver(Invoke(resolution())).resolve(event, resolved_policy())
    secrets = SecretResolver(SecretClient())
    return event, connection, secrets.smtp(event, connection), secrets.recipient(event)


class TemplateTests(unittest.TestCase):
    def test_builds_one_plain_text_spanish_message_with_stable_safe_headers(self):
        from src.templates import render_message

        event, connection, _smtp, recipient = dependencies()
        first = render_message(event, connection, recipient)
        second = render_message(event, connection, recipient)

        self.assertEqual(first.get_content_type(), "text/plain")
        self.assertEqual(first["From"], "notificaciones@zoolandingpage.com.mx")
        self.assertEqual(first["Reply-To"], "soporte@zoolandingpage.com.mx")
        self.assertEqual(first["To"], "operator@example.test")
        self.assertEqual(first["Subject"], "Pago recibido")
        self.assertEqual(first["Message-ID"], second["Message-ID"])
        self.assertIn("orden order-1", first.get_content())
        self.assertIn("900.00 MXN", first.get_content())
        self.assertNotIn("http", first.as_string().lower())
        self.assertNotIn("html", first.as_string().lower())
        self.assertEqual(list(first.iter_attachments()), [])

    def test_failed_template_is_fixed_and_header_injection_is_rejected(self):
        from dataclasses import replace

        from src.integrations_gateway import SMTPConnection
        from src.templates import TemplateError, render_message

        event, connection, _smtp, recipient = dependencies()
        failed = replace(event, notification_type="payment-failed", template_id="payment-failed-v1")
        self.assertEqual(render_message(failed, connection, recipient)["Subject"], "Cobro no completado")

        for changed in (
            replace(connection, from_local_part="bad\r\nBcc"),
            replace(connection, reply_to_local_part="bad\x00"),
            replace(connection, canonical_sending_domain="other.example.test"),
            replace(recipient, address="operator@example.test\r\nBcc:x@example.test"),
            replace(recipient, address="Display Name <operator@example.test>"),
            replace(recipient, address=".operator@example.test"),
            replace(recipient, address="operator.@example.test"),
            replace(recipient, address="operator..alerts@example.test"),
            replace(connection, from_local_part="billing..alerts"),
        ):
            with self.subTest(changed=changed), self.assertRaises(TemplateError):
                render_message(event, changed if isinstance(changed, SMTPConnection) else connection, changed if not isinstance(changed, SMTPConnection) else recipient)


class FakeSMTP:
    error = None
    quit_error = None
    instances = []

    def __init__(self, host, port, *, timeout, context):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context
        self.login_calls = []
        self.messages = []
        self.starttls_calls = 0
        type(self).instances.append(self)

    def login(self, username, password):
        self.login_calls.append((username, password))

    def send_message(self, message, from_addr=None, to_addrs=None):
        if type(self).error is not None:
            raise type(self).error
        self.messages.append((message, from_addr, to_addrs))
        return {}

    def starttls(self, *args, **kwargs):
        self.starttls_calls += 1
        raise AssertionError("STARTTLS is forbidden")

    def quit(self):
        if type(self).quit_error is not None:
            raise type(self).quit_error
        return 221, b"ok"

    def close(self):
        return None


class SMTPAdapterTests(unittest.TestCase):
    def setUp(self):
        FakeSMTP.error = None
        FakeSMTP.quit_error = None
        FakeSMTP.instances = []

    def send(self):
        from src.smtp_adapter import SMTPAdapter
        from src.templates import render_message

        event, connection, smtp_secret, recipient = dependencies()
        message = render_message(event, connection, recipient)
        return SMTPAdapter(factory=FakeSMTP).send(connection, smtp_secret, message)

    def test_uses_implicit_tls_default_context_and_quit_cannot_reverse_acceptance(self):
        FakeSMTP.quit_error = smtplib.SMTPServerDisconnected("after acceptance")

        result = self.send()

        self.assertEqual(result.outcome, "accepted_by_smtp")
        instance = FakeSMTP.instances[0]
        self.assertEqual((instance.host, instance.port, instance.timeout), ("mail.smtp2go.com", 465, 10))
        self.assertIsInstance(instance.context, ssl.SSLContext)
        self.assertEqual(instance.context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(instance.context.check_hostname)
        self.assertEqual(instance.starttls_calls, 0)
        self.assertEqual(len(instance.messages[0][2]), 1)

    def test_classifies_confirmed_4xx_5xx_auth_quota_and_ambiguous_failures(self):
        cases = (
            (smtplib.SMTPDataError(450, b"transient sensitive"), ("retryable", "smtp_transient")),
            (smtplib.SMTPDataError(550, b"permanent sensitive"), ("failed", "smtp_permanent")),
            (smtplib.SMTPDataError(550, b"username rate limit exceeded"), ("retryable", "smtp_throttled")),
            (smtplib.SMTPDataError(550, b"Your username has exceeded the allowed sending rate"), ("retryable", "smtp_throttled")),
            (smtplib.SMTPDataError(550, b"Your IP address exceeded the allowed sending rate"), ("retryable", "smtp_throttled")),
            (smtplib.SMTPDataError(421, b"Too many concurrent SMTP connections"), ("retryable", "smtp_throttled")),
            (smtplib.SMTPDataError(421, b"Too many connections from that IP address"), ("retryable", "smtp_throttled")),
            (smtplib.SMTPAuthenticationError(535, b"auth sensitive"), ("failed", "smtp_authentication")),
            (smtplib.SMTPAuthenticationError(454, b"temporary auth sensitive"), ("retryable", "smtp_transient")),
            (smtplib.SMTPDataError(552, b"quota sensitive"), ("failed", "smtp_quota")),
            (socket.timeout("sensitive"), ("uncertain", "smtp_ambiguous")),
            (smtplib.SMTPServerDisconnected("sensitive"), ("uncertain", "smtp_ambiguous")),
            (ssl.SSLCertVerificationError("hostname sensitive"), ("uncertain", "smtp_ambiguous")),
        )
        for error, expected in cases:
            FakeSMTP.error = error
            FakeSMTP.instances = []
            with self.subTest(error=type(error).__name__):
                result = self.send()
                self.assertEqual((result.outcome, result.reason_code), expected)
                self.assertNotIn("sensitive", repr(result))

    def test_retries_network_failures_before_smtp_data(self):
        from src.smtp_adapter import SMTPAdapter
        from src.templates import render_message

        event, connection, smtp_secret, recipient = dependencies()
        message = render_message(event, connection, recipient)

        def failed_connection(*_args, **_kwargs):
            raise socket.timeout("sensitive connection detail")

        class FailedLoginSMTP(FakeSMTP):
            def login(self, username, password):
                del username, password
                raise smtplib.SMTPServerDisconnected("sensitive login detail")

        for factory in (failed_connection, FailedLoginSMTP):
            with self.subTest(factory=factory):
                result = SMTPAdapter(factory=factory).send(connection, smtp_secret, message)
                self.assertEqual((result.outcome, result.reason_code), ("retryable", "smtp_transient"))
                self.assertNotIn("sensitive", repr(result))

    def test_fails_closed_when_tls_certificate_validation_fails_before_smtp_data(self):
        from src.smtp_adapter import SMTPAdapter
        from src.templates import render_message

        event, connection, smtp_secret, recipient = dependencies()
        message = render_message(event, connection, recipient)

        def invalid_certificate(*_args, **_kwargs):
            raise ssl.SSLCertVerificationError("sensitive certificate detail")

        result = SMTPAdapter(factory=invalid_certificate).send(connection, smtp_secret, message)

        self.assertEqual((result.outcome, result.reason_code), ("failed", "smtp_permanent"))
        self.assertNotIn("sensitive", repr(result))

    def test_sanitizes_partial_recipient_errors_and_rejects_endpoint_downgrade(self):
        from dataclasses import replace

        from src.smtp_adapter import SMTPAdapter, SMTPConfigurationError
        from src.templates import render_message

        FakeSMTP.error = smtplib.SMTPRecipientsRefused({
            "operator@example.test": (450, b"sensitive address response")
        })
        result = self.send()
        self.assertEqual((result.outcome, result.reason_code), ("retryable", "smtp_transient"))
        self.assertNotIn("operator", repr(result))

        event, connection, smtp_secret, recipient = dependencies()
        message = render_message(event, connection, recipient)
        for changed in (replace(connection, host="other"), replace(connection, port=587), replace(connection, tls_mode="starttls")):
            with self.subTest(changed=changed), self.assertRaises(SMTPConfigurationError):
                SMTPAdapter(factory=FakeSMTP).send(changed, smtp_secret, message)

    def test_unexpected_smtp_send_result_is_ambiguous_not_accepted(self):
        from src.smtp_adapter import SMTPAdapter
        from src.templates import render_message

        class UnexpectedSMTP(FakeSMTP):
            def send_message(self, message, from_addr=None, to_addrs=None):
                del message, from_addr, to_addrs
                return None

        event, connection, smtp_secret, recipient = dependencies()
        result = SMTPAdapter(factory=UnexpectedSMTP).send(
            connection,
            smtp_secret,
            render_message(event, connection, recipient),
        )

        self.assertEqual((result.outcome, result.reason_code), ("uncertain", "smtp_ambiguous"))


if __name__ == "__main__":
    unittest.main()
