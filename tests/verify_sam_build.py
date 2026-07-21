import importlib
import secrets as stdlib_secrets
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / ".aws-sam" / "build" / "SmtpDeliveryWorkerFunction"


def main():
    if not BUILD.is_dir():
        raise SystemExit("SAM build artifact is missing")
    forbidden = {"tests", ".git", ".github", "template.yaml", "README.md", "AGENTS.md"}
    names = {path.name for path in BUILD.iterdir()}
    overlap = forbidden.intersection(names)
    if overlap:
        raise SystemExit(f"forbidden build entries: {sorted(overlap)}")
    sys.path.insert(0, str(BUILD))
    module = importlib.import_module("handlers.smtp_delivery_worker")
    if not callable(module.lambda_handler):
        raise SystemExit("built handler is not callable")
    runtime = importlib.import_module("runtime")
    if not callable(runtime.notification_worker):
        raise SystemExit("built runtime composition is not callable")
    secret_resolver = importlib.import_module("secret_resolver")
    if not callable(secret_resolver.SecretResolver):
        raise SystemExit("built secret resolver is not callable")
    if Path(stdlib_secrets.__file__).resolve().parent == BUILD:
        raise SystemExit("built artifact shadows stdlib secrets")
    print("verified notifications SAM build")


if __name__ == "__main__":
    main()
