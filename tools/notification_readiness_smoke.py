"""Redacted, read-only deployment identifier smoke for Notifications."""

from __future__ import annotations

import argparse
import json
import re
from typing import Any


_ENVIRONMENTS = {"test", "production"}
_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*$")
_AUTH_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "ExpiredToken",
    "ExpiredTokenException",
    "InvalidClientTokenId",
    "MissingAuthenticationToken",
    "SignatureDoesNotMatch",
    "UnrecognizedClientException",
}
_AUTH_ERROR_NAMES = {
    "NoCredentialsError",
    "PartialCredentialsError",
}


def expected_parameter_paths(environment: str) -> dict[str, str]:
    prefix = f"/zoolanding/{environment}"
    return {
        "config_registry_table": f"{prefix}/config/registry-table-name",
        "config_payload_bucket": f"{prefix}/config/payload-bucket-name",
        "commerce_topic_arn": f"{prefix}/topics/commerce-notification-requests-arn",
        "integrations_api_id": f"{prefix}/services/integrations/api-id",
        "smtp_worker_role_arn": f"{prefix}/services/notifications/smtp-worker-role-arn",
        "notification_queue_arn": f"{prefix}/queues/notification-requests-arn",
        "delivery_ledger_name": f"{prefix}/tables/notifications-delivery-ledger-name",
    }


def run_smoke(environment: object, region: object, ssm_client: Any) -> dict[str, object]:
    if (
        type(environment) is not str
        or environment not in _ENVIRONMENTS
        or type(region) is not str
        or _REGION.fullmatch(region) is None
        or ssm_client is None
    ):
        return _result("missing_input")
    paths = expected_parameter_paths(environment)
    try:
        response = ssm_client.get_parameters(
            Names=list(paths.values()),
            WithDecryption=False,
        )
    except Exception as error:
        return _result("auth_failure" if _is_auth_failure(error) else "provider_failure")
    if not isinstance(response, dict):
        return _result("provider_failure")
    invalid = response.get("InvalidParameters")
    parameters = response.get("Parameters")
    if not isinstance(invalid, list) or not isinstance(parameters, list):
        return _result("provider_failure")
    if invalid or len(parameters) != len(paths):
        return _result("propagation_delay")
    resolved: dict[str, str] = {}
    for item in parameters:
        if not isinstance(item, dict):
            return _result("configuration_failure")
        name = item.get("Name")
        value = item.get("Value")
        if name not in paths.values() or item.get("Type") != "String" or type(value) is not str or name in resolved:
            return _result("configuration_failure")
        resolved[name] = value
    if set(resolved) != set(paths.values()) or not _values_are_valid(paths, resolved, region):
        return _result("configuration_failure")
    return {"ok": True, "category": "ready"}


def _values_are_valid(paths: dict[str, str], values: dict[str, str], region: str) -> bool:
    account = r"[0-9]{12}"
    partition = r"aws(?:-us-gov|-cn)?"
    validators = {
        "config_registry_table": r"[A-Za-z0-9_.-]{3,255}",
        "config_payload_bucket": r"[a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9])",
        "commerce_topic_arn": rf"arn:{partition}:sns:{re.escape(region)}:{account}:[A-Za-z0-9_.-]+",
        "integrations_api_id": r"[a-z0-9]{10}",
        "smtp_worker_role_arn": rf"arn:{partition}:iam::{account}:role/[A-Za-z0-9+=,.@_/-]+",
        "notification_queue_arn": rf"arn:{partition}:sqs:{re.escape(region)}:{account}:[A-Za-z0-9_-]+",
        "delivery_ledger_name": r"[A-Za-z0-9_.-]{3,255}",
    }
    return all(
        re.fullmatch(validators[key], values[paths[key]]) is not None
        for key in paths
    )


def _error_code(error: Exception) -> str:
    response = getattr(error, "response", None)
    if not isinstance(response, dict):
        return ""
    details = response.get("Error")
    if not isinstance(details, dict):
        return ""
    code = details.get("Code")
    return code if type(code) is str else ""


def _is_auth_failure(error: Exception) -> bool:
    return type(error).__name__ in _AUTH_ERROR_NAMES or _error_code(error) in _AUTH_CODES


def _result(category: str) -> dict[str, object]:
    return {"ok": False, "category": category}


def _ssm_client(region: str):
    import boto3

    return boto3.client("ssm", region_name=region)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check redacted Notifications deployment identifiers.")
    parser.add_argument("--environment")
    parser.add_argument("--region")
    arguments = parser.parse_args(argv)
    if arguments.environment not in _ENVIRONMENTS or type(arguments.region) is not str or _REGION.fullmatch(arguments.region) is None:
        result = _result("missing_input")
    else:
        try:
            client = _ssm_client(arguments.region)
        except Exception as error:
            result = _result("auth_failure" if _is_auth_failure(error) else "provider_failure")
        else:
            result = run_smoke(arguments.environment, arguments.region, client)
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
