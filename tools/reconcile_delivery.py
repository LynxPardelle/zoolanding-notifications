"""Manually reconcile one ambiguous SMTP attempt after provider review."""

from __future__ import annotations

import argparse
import re
import time
from typing import Any


_SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}", re.ASCII)
_DEDUPE = re.compile(r"[a-f0-9]{64}", re.ASCII)


class ReconciliationError(RuntimeError):
    pass


def reconcile_delivery(
    table: Any,
    *,
    environment: str,
    tenant_id: str,
    draft_id: str,
    dedupe_key: str,
    expected_revision: int,
    decision: str,
    approval_id: str,
    now_epoch: int,
) -> None:
    if (
        environment not in {"test", "production"}
        or any(type(value) is not str or _SAFE_ID.fullmatch(value) is None for value in (tenant_id, draft_id, approval_id))
        or type(dedupe_key) is not str
        or _DEDUPE.fullmatch(dedupe_key) is None
        or type(expected_revision) is not int
        or expected_revision < 1
        or decision not in {"accepted", "retry"}
        or type(now_epoch) is not int
        or now_epoch < 0
    ):
        raise ReconciliationError("delivery reconciliation input is invalid")
    pk = f"ENV#{environment}#TENANT#{tenant_id}#DRAFT#{draft_id}"
    if decision == "accepted":
        update = (
            "SET #state = :accepted, #reason = :reason, #accepted = :now, "
            "#updated = :now, #approval = :approval, #revision = :next "
            "REMOVE #uncertain"
        )
        names = {
            "#state": "state", "#reason": "reasonCode", "#accepted": "acceptedAt",
            "#updated": "updatedAt", "#approval": "reconciliationApprovalId",
            "#revision": "revision", "#uncertain": "uncertainAt",
        }
        values = {
            ":accepted": "accepted_by_smtp",
            ":reason": "operator_confirmed_acceptance",
            ":now": now_epoch,
            ":approval": approval_id,
            ":next": expected_revision + 1,
            ":uncertain": "uncertain",
            ":expected": expected_revision,
        }
    else:
        update = (
            "SET #state = :prepared, #updated = :now, #approval = :approval, "
            "#revision = :next REMOVE #uncertain, #reason"
        )
        names = {
            "#state": "state", "#updated": "updatedAt", "#approval": "reconciliationApprovalId",
            "#revision": "revision", "#uncertain": "uncertainAt", "#reason": "reasonCode",
            "#attempts": "attempts", "#max_attempts": "maxAttempts",
        }
        values = {
            ":prepared": "prepared",
            ":now": now_epoch,
            ":approval": approval_id,
            ":next": expected_revision + 1,
            ":uncertain": "uncertain",
            ":expected": expected_revision,
        }
    try:
        condition = "#state = :uncertain AND #revision = :expected"
        if decision == "retry":
            condition += " AND #attempts < #max_attempts"
        table.update_item(
            Key={"pk": pk, "sk": f"DELIVERY#{dedupe_key}"},
            UpdateExpression=update,
            ConditionExpression=condition,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )
    except Exception:
        raise ReconciliationError("delivery reconciliation conflicted") from None
    print(f"delivery-reconciled-{decision}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Reconcile one uncertain SMTP attempt")
    parser.add_argument("decision", choices=("accepted", "retry"))
    parser.add_argument("--table-name", required=True)
    parser.add_argument("--environment", required=True, choices=("test", "production"))
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--draft-id", required=True)
    parser.add_argument("--dedupe-key", required=True)
    parser.add_argument("--expected-revision", required=True, type=int)
    parser.add_argument("--approval-id", required=True)
    args = parser.parse_args()
    import boto3

    table = boto3.resource("dynamodb").Table(args.table_name)
    try:
        reconcile_delivery(
            table,
            environment=args.environment,
            tenant_id=args.tenant_id,
            draft_id=args.draft_id,
            dedupe_key=args.dedupe_key,
            expected_revision=args.expected_revision,
            decision=args.decision,
            approval_id=args.approval_id,
            now_epoch=int(time.time()),
        )
    except ReconciliationError:
        raise SystemExit("delivery-reconciliation-failed") from None


if __name__ == "__main__":
    main()
