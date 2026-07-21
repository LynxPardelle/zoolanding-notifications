import contextlib
import io
from pathlib import Path
import subprocess
import sys
import unittest


class SecretsClient:
    def __init__(self):
        self.created = []
        self.tagged = []

    def create_secret(self, **kwargs):
        self.created.append(kwargs)
        return {"ARN": "not-printed"}

    def tag_resource(self, **kwargs):
        self.tagged.append(kwargs)
        return {}


class Table:
    def __init__(self):
        self.calls = []

    def update_item(self, **kwargs):
        self.calls.append(kwargs)
        return {}


class OperatorToolTests(unittest.TestCase):
    def test_recipient_tool_supports_the_documented_direct_script_entrypoint(self):
        result = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve().parents[1] / "tools" / "manage_recipient_secret.py"),
                "--help",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("ModuleNotFoundError", result.stderr)

    def test_recipient_create_is_one_version_once_and_prints_no_address_or_secret_path(self):
        from tools.manage_recipient_secret import create_recipient

        client = SecretsClient()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            create_recipient(
                client,
                environment="test",
                tenant_id="tenant-a",
                draft_id="draft-a",
                recipient_set_id="billing-operators",
                recipient_set_version=1,
                recipient_member_id="primary",
                address="operator@example.test",
            )

        self.assertEqual(len(client.created), 1)
        request = client.created[0]
        self.assertNotIn("ForceOverwriteReplicaSecret", request)
        self.assertNotIn("ClientRequestToken", request)
        self.assertIn("/1/primary", request["Name"])
        self.assertIn("operator@example.test", request["SecretString"])
        self.assertEqual(stdout.getvalue().strip(), "recipient-version-created")
        self.assertNotIn("operator", stdout.getvalue())
        self.assertNotIn("/zoolanding/", stdout.getvalue())

        with contextlib.redirect_stdout(io.StringIO()):
            create_recipient(
                client,
                environment="test",
                tenant_id="tenant-a",
                draft_id="draft-a",
                recipient_set_id="billing-operators",
                recipient_set_version=2,
                recipient_member_id="primary",
                address="new@example.test",
            )
        self.assertNotEqual(client.created[0]["Name"], client.created[1]["Name"])

    def test_recipient_create_rejects_ambiguous_dot_local_parts_before_aws(self):
        from tools.manage_recipient_secret import RecipientToolError, create_recipient

        client = SecretsClient()
        for address in (
            ".operator@example.test",
            "operator.@example.test",
            "operator..alerts@example.test",
        ):
            with self.subTest(address=address), self.assertRaises(RecipientToolError):
                create_recipient(
                    client,
                    environment="test",
                    tenant_id="tenant-a",
                    draft_id="draft-a",
                    recipient_set_id="billing-operators",
                    recipient_set_version=1,
                    recipient_member_id="primary",
                    address=address,
                )
        self.assertEqual(client.created, [])

    def test_recipient_revoke_changes_only_enabled_tag(self):
        from tools.manage_recipient_secret import revoke_recipient

        client = SecretsClient()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            revoke_recipient(
                client,
                environment="production",
                tenant_id="tenant-a",
                draft_id="draft-a",
                recipient_set_id="billing-operators",
                recipient_set_version=3,
                recipient_member_id="primary",
            )
        self.assertEqual(client.tagged[0]["Tags"], [{"Key": "zoolanding:enabled", "Value": "false"}])
        self.assertEqual(stdout.getvalue().strip(), "recipient-version-revoked")

    def test_manual_reconciliation_allows_only_two_decisions_and_opaque_approval(self):
        from tools.reconcile_delivery import ReconciliationError, reconcile_delivery

        for decision in ("accepted", "retry"):
            table = Table()
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                reconcile_delivery(
                    table,
                    environment="test",
                    tenant_id="tenant-a",
                    draft_id="draft-a",
                    dedupe_key="a" * 64,
                    expected_revision=3,
                    decision=decision,
                    approval_id="approval-1",
                    now_epoch=1_800_000_000,
                )
            request = table.calls[0]
            self.assertIn("#state = :uncertain", request["ConditionExpression"])
            if decision == "retry":
                self.assertIn("#attempts < #max_attempts", request["ConditionExpression"])
                self.assertEqual(request["ExpressionAttributeNames"]["#attempts"], "attempts")
                self.assertEqual(request["ExpressionAttributeNames"]["#max_attempts"], "maxAttempts")
            self.assertEqual(request["ExpressionAttributeValues"][":approval"], "approval-1")
            self.assertEqual(stdout.getvalue().strip(), f"delivery-reconciled-{decision}")

        for decision, approval in (("resend", "approval-1"), ("retry", "bad approval")):
            with self.subTest(decision=decision, approval=approval), self.assertRaises(ReconciliationError):
                reconcile_delivery(
                    Table(), environment="test", tenant_id="tenant-a", draft_id="draft-a",
                    dedupe_key="a" * 64, expected_revision=3, decision=decision,
                    approval_id=approval, now_epoch=1_800_000_000,
                )

        for dedupe_key in (
            "a" * 63,
            "a" * 65,
            "A" * 64,
            "not-a-canonical-event-hash",
        ):
            table = Table()
            with self.subTest(dedupe_key=dedupe_key), self.assertRaises(ReconciliationError):
                reconcile_delivery(
                    table, environment="test", tenant_id="tenant-a", draft_id="draft-a",
                    dedupe_key=dedupe_key, expected_revision=3, decision="retry",
                    approval_id="approval-1", now_epoch=1_800_000_000,
                )
            self.assertEqual(table.calls, [])

    def test_manual_retry_fails_closed_when_the_pinned_attempt_budget_is_exhausted(self):
        from tools.reconcile_delivery import ReconciliationError, reconcile_delivery

        class ExhaustedTable:
            def __init__(self):
                self.calls = []

            def update_item(self, **kwargs):
                self.calls.append(kwargs)
                if "#attempts < #max_attempts" not in kwargs["ConditionExpression"]:
                    raise AssertionError("retry budget condition is missing")
                raise RuntimeError("simulated conditional conflict")

        table = ExhaustedTable()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(ReconciliationError):
            reconcile_delivery(
                table,
                environment="test",
                tenant_id="tenant-a",
                draft_id="draft-a",
                dedupe_key="a" * 64,
                expected_revision=3,
                decision="retry",
                approval_id="approval-1",
                now_epoch=1_800_000_000,
            )
        self.assertEqual(len(table.calls), 1)
        self.assertIn("#attempts < #max_attempts", table.calls[0]["ConditionExpression"])
        self.assertEqual(stdout.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
