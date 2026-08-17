import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


class Client:
    def __init__(self):
        self.calls = []

    def put_metric_data(self, **kwargs):
        self.calls.append(kwargs)


class RuntimeTests(unittest.TestCase):
    def test_runtime_import_is_stable_when_stdlib_secrets_is_preloaded(self):
        source = Path(__file__).resolve().parents[1] / "src"
        code = (
            "import secrets as stdlib_secrets,sys;"
            f"sys.path.insert(0,{str(source)!r});"
            "import runtime,secret_resolver;"
            "assert 'site-packages' not in (stdlib_secrets.__file__ or '');"
            "assert callable(runtime.notification_worker);"
            "assert callable(secret_resolver.SecretResolver)"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_runtime_rejects_dev_and_missing_configuration_before_aws_clients(self):
        from src import runtime

        with patch.dict(os.environ, {"ENVIRONMENT_NAME": "dev"}, clear=True):
            with self.assertRaises(RuntimeError):
                runtime.notification_worker()

    def test_operational_metrics_have_only_the_non_sensitive_environment_dimension(self):
        from src.runtime import CloudWatchMetrics

        client = Client()
        metrics = CloudWatchMetrics(client)
        metrics.circuit_opened("test", "smtp_authentication")
        metrics.circuit_opened("production", "smtp_quota")
        metrics.smtp_throttled("test")
        metrics.test_live_mismatch("production")
        metrics.circuit_opened("dev", "smtp_quota")
        metrics.circuit_opened("test", "provider text")
        metrics.smtp_throttled("dev")
        metrics.test_live_mismatch("dev")

        self.assertEqual(
            client.calls,
            [
                {
                    "Namespace": "Zoolanding/Notifications",
                    "MetricData": [
                        {
                            "MetricName": "CircuitOpen", "Unit": "Count", "Value": 1,
                            "Dimensions": [{"Name": "Environment", "Value": "test"}],
                        },
                        {
                            "MetricName": "Smtp2GoAuthenticationRejected", "Unit": "Count", "Value": 1,
                            "Dimensions": [{"Name": "Environment", "Value": "test"}],
                        },
                    ],
                },
                {
                    "Namespace": "Zoolanding/Notifications",
                    "MetricData": [
                        {
                            "MetricName": "CircuitOpen", "Unit": "Count", "Value": 1,
                            "Dimensions": [{"Name": "Environment", "Value": "production"}],
                        },
                        {
                            "MetricName": "Smtp2GoQuotaRejected", "Unit": "Count", "Value": 1,
                            "Dimensions": [{"Name": "Environment", "Value": "production"}],
                        },
                    ],
                },
                {
                    "Namespace": "Zoolanding/Notifications",
                    "MetricData": [{
                        "MetricName": "Smtp2GoThrottleRejected", "Unit": "Count", "Value": 1,
                        "Dimensions": [{"Name": "Environment", "Value": "test"}],
                    }],
                },
                {
                    "Namespace": "Zoolanding/Notifications",
                    "MetricData": [{
                        "MetricName": "TestLiveMismatch", "Unit": "Count", "Value": 1,
                        "Dimensions": [{"Name": "Environment", "Value": "production"}],
                    }],
                },
            ],
        )
        for call, environment in zip(client.calls, ("test", "production", "test", "production"), strict=True):
            for datum in call["MetricData"]:
                self.assertEqual(
                    datum["Dimensions"],
                    [{"Name": "Environment", "Value": environment}],
                )


if __name__ == "__main__":
    unittest.main()
