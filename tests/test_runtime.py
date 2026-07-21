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

    def test_circuit_metric_is_closed_and_has_no_scope_or_reason_dimension(self):
        from src.runtime import CloudWatchMetrics

        client = Client()
        metrics = CloudWatchMetrics(client)
        metrics.circuit_opened("test", "smtp_authentication")
        metrics.circuit_opened("production", "smtp_quota")
        metrics.circuit_opened("dev", "smtp_quota")
        metrics.circuit_opened("test", "provider text")

        self.assertEqual(
            client.calls,
            [
                {
                    "Namespace": "Zoolanding/Notifications",
                    "MetricData": [{"MetricName": "CircuitOpen", "Unit": "Count", "Value": 1}],
                },
                {
                    "Namespace": "Zoolanding/Notifications",
                    "MetricData": [{"MetricName": "CircuitOpen", "Unit": "Count", "Value": 1}],
                },
            ],
        )


if __name__ == "__main__":
    unittest.main()
