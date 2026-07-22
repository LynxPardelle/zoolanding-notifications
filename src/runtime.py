"""Production dependency composition; no dev or provider fallback."""

from __future__ import annotations

import os

try:
    from common.published_policy import PublishedPolicyResolver
    from delivery_store import DeliveryStore, DynamoDeliveryBackend
    from domain.delivery import NotificationWorker
    from integrations_gateway import ConnectionResolver, SignedAWSIAMInvoker
    from secret_resolver import SecretResolver
    from smtp_adapter import SMTPAdapter
except ModuleNotFoundError:
    from src.common.published_policy import PublishedPolicyResolver
    from src.delivery_store import DeliveryStore, DynamoDeliveryBackend
    from src.domain.delivery import NotificationWorker
    from src.integrations_gateway import ConnectionResolver, SignedAWSIAMInvoker
    from src.secret_resolver import SecretResolver
    from src.smtp_adapter import SMTPAdapter


class CloudWatchMetrics:
    def __init__(self, client):
        self._client = client

    def circuit_opened(self, environment: str, reason_code: str) -> None:
        if environment not in {"test", "production"} or reason_code not in {"smtp_authentication", "smtp_quota"}:
            return
        reason_metric = {
            "smtp_authentication": "Smtp2GoAuthenticationRejected",
            "smtp_quota": "Smtp2GoQuotaRejected",
        }[reason_code]
        dimensions = [{"Name": "Environment", "Value": environment}]
        self._client.put_metric_data(
            Namespace="Zoolanding/Notifications",
            MetricData=[
                {"MetricName": "CircuitOpen", "Unit": "Count", "Value": 1, "Dimensions": dimensions},
                {"MetricName": reason_metric, "Unit": "Count", "Value": 1, "Dimensions": dimensions},
            ],
        )

    def smtp_throttled(self, environment: str) -> None:
        self._count(environment, "Smtp2GoThrottleRejected")

    def test_live_mismatch(self, environment: str) -> None:
        self._count(environment, "TestLiveMismatch")

    def _count(self, environment: str, metric_name: str) -> None:
        if environment not in {"test", "production"}:
            return
        self._client.put_metric_data(
            Namespace="Zoolanding/Notifications",
            MetricData=[{
                "MetricName": metric_name,
                "Unit": "Count",
                "Value": 1,
                "Dimensions": [{"Name": "Environment", "Value": environment}],
            }],
        )


def notification_worker() -> NotificationWorker:
    environment = os.environ.get("ENVIRONMENT_NAME", "")
    required = {
        "DELIVERY_LEDGER_TABLE_NAME": os.environ.get("DELIVERY_LEDGER_TABLE_NAME", ""),
        "CONFIG_REGISTRY_TABLE_NAME": os.environ.get("CONFIG_REGISTRY_TABLE_NAME", ""),
        "CONFIG_PAYLOADS_BUCKET_NAME": os.environ.get("CONFIG_PAYLOADS_BUCKET_NAME", ""),
        "INTEGRATIONS_API_ID": os.environ.get("INTEGRATIONS_API_ID", ""),
        "INTEGRATIONS_URL_SUFFIX": os.environ.get("INTEGRATIONS_URL_SUFFIX", ""),
        "AWS_REGION": os.environ.get("AWS_REGION", ""),
    }
    if environment not in {"test", "production"} or any(not value for value in required.values()):
        raise RuntimeError("notification runtime is unavailable")
    import boto3

    dynamodb = boto3.resource("dynamodb")
    policies = PublishedPolicyResolver(
        dynamodb.Table(required["CONFIG_REGISTRY_TABLE_NAME"]),
        boto3.client("s3"),
        required["CONFIG_PAYLOADS_BUCKET_NAME"],
    )
    invoker = SignedAWSIAMInvoker(
        required["INTEGRATIONS_API_ID"],
        environment,
        required["AWS_REGION"],
        required["INTEGRATIONS_URL_SUFFIX"],
    )
    return NotificationWorker(
        policies,
        ConnectionResolver(invoker),
        SecretResolver(boto3.client("secretsmanager")),
        DeliveryStore(DynamoDeliveryBackend(dynamodb.Table(required["DELIVERY_LEDGER_TABLE_NAME"]))),
        SMTPAdapter(),
        CloudWatchMetrics(boto3.client("cloudwatch")),
    )
