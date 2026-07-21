"""SQS partial-batch entry point for outbound SMTP delivery."""

from __future__ import annotations

import os
import time
from typing import Any

try:
    from contracts.events import parse_event_json
except ModuleNotFoundError:
    from src.contracts.events import parse_event_json


def process_batch(
    batch: object,
    worker: Any,
    *,
    now_epoch: int,
    expected_environment: str,
) -> dict[str, list[dict[str, str]]]:
    records = batch.get("Records") if isinstance(batch, dict) else None
    if not isinstance(records, list) or len(records) > 10 or expected_environment not in {"test", "production"}:
        raise ValueError("notification batch is invalid")
    failures: list[dict[str, str]] = []
    seen: set[str] = set()
    for record in records:
        message_id = record.get("messageId") if isinstance(record, dict) else None
        body = record.get("body") if isinstance(record, dict) else None
        if (
            type(message_id) is not str
            or not 1 <= len(message_id) <= 128
            or message_id in seen
        ):
            raise ValueError("notification batch is invalid")
        if type(body) is not str:
            failures.append({"itemIdentifier": message_id})
            continue
        seen.add(message_id)
        try:
            event = parse_event_json(body)
            if event.environment != expected_environment:
                raise ValueError
            outcome = worker.process(event, now_epoch=now_epoch)
            if outcome != "processed":
                failures.append({"itemIdentifier": message_id})
        except Exception:
            failures.append({"itemIdentifier": message_id})
    return {"batchItemFailures": failures}


def lambda_handler(event, context):
    del context
    environment = os.environ.get("ENVIRONMENT_NAME", "")
    worker = _runtime_worker()
    return process_batch(
        event,
        worker,
        now_epoch=int(time.time()),
        expected_environment=environment,
    )


def _runtime_worker():
    try:
        from runtime import notification_worker
    except ModuleNotFoundError:
        from src.runtime import notification_worker

    return notification_worker()
