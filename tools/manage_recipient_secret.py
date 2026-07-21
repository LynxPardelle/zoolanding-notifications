"""Create-once or revoke one immutable recipient-secret version."""

from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
import re
import sys
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.common.email_address import is_valid_mailbox


_SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}", re.ASCII)
class RecipientToolError(RuntimeError):
    pass


def create_recipient(
    client: Any,
    *,
    environment: str,
    tenant_id: str,
    draft_id: str,
    recipient_set_id: str,
    recipient_set_version: int,
    recipient_member_id: str,
    address: str,
) -> None:
    path = _path(
        environment,
        tenant_id,
        draft_id,
        recipient_set_id,
        recipient_set_version,
        recipient_member_id,
    )
    if not is_valid_mailbox(address):
        raise RecipientToolError("recipient address is invalid")
    try:
        client.create_secret(
            Name=path,
            Description="Zoolanding immutable notification recipient version",
            SecretString=json.dumps(
                {"version": 1, "address": address},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ),
            Tags=[
                {"Key": "zoolanding:environment", "Value": environment},
                {"Key": "zoolanding:tenant-id", "Value": tenant_id},
                {"Key": "zoolanding:draft-id", "Value": draft_id},
                {"Key": "zoolanding:secret-purpose", "Value": "recipient"},
                {"Key": "zoolanding:enabled", "Value": "true"},
                {"Key": "zoolanding:recipient-set-id", "Value": recipient_set_id},
                {"Key": "zoolanding:recipient-set-version", "Value": str(recipient_set_version)},
                {"Key": "zoolanding:recipient-member-id", "Value": recipient_member_id},
            ],
        )
    except Exception:
        raise RecipientToolError("recipient version creation failed") from None
    print("recipient-version-created")


def revoke_recipient(
    client: Any,
    *,
    environment: str,
    tenant_id: str,
    draft_id: str,
    recipient_set_id: str,
    recipient_set_version: int,
    recipient_member_id: str,
) -> None:
    path = _path(
        environment,
        tenant_id,
        draft_id,
        recipient_set_id,
        recipient_set_version,
        recipient_member_id,
    )
    try:
        client.tag_resource(
            SecretId=path,
            Tags=[{"Key": "zoolanding:enabled", "Value": "false"}],
        )
    except Exception:
        raise RecipientToolError("recipient version revocation failed") from None
    print("recipient-version-revoked")


def _path(environment, tenant_id, draft_id, recipient_set_id, version, member_id):
    if environment not in {"test", "production"}:
        raise RecipientToolError("recipient scope is invalid")
    values = (tenant_id, draft_id, recipient_set_id, member_id)
    if any(type(value) is not str or _SAFE_ID.fullmatch(value) is None for value in values):
        raise RecipientToolError("recipient scope is invalid")
    if type(version) is not int or not 1 <= version <= 2_147_483_647:
        raise RecipientToolError("recipient version is invalid")
    return (
        f"/zoolanding/{environment}/{tenant_id}/{draft_id}/notifications/"
        f"recipients/{recipient_set_id}/{version}/{member_id}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage one immutable recipient version")
    parser.add_argument("operation", choices=("create", "revoke"))
    parser.add_argument("--environment", required=True, choices=("test", "production"))
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--draft-id", required=True)
    parser.add_argument("--recipient-set-id", required=True)
    parser.add_argument("--recipient-set-version", required=True, type=int)
    parser.add_argument("--recipient-member-id", required=True)
    args = parser.parse_args()
    import boto3

    client = boto3.client("secretsmanager")
    common = {
        "environment": args.environment,
        "tenant_id": args.tenant_id,
        "draft_id": args.draft_id,
        "recipient_set_id": args.recipient_set_id,
        "recipient_set_version": args.recipient_set_version,
        "recipient_member_id": args.recipient_member_id,
    }
    try:
        if args.operation == "create":
            create_recipient(client, address=getpass.getpass("Recipient address: "), **common)
        else:
            revoke_recipient(client, **common)
    except RecipientToolError:
        raise SystemExit("recipient-operation-failed") from None


if __name__ == "__main__":
    main()
