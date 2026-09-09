"""Plaso JSON and JSONL ingestion."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Iterator

from .models import EvidenceEvent, parse_timestamp, stable_id


FIELD_ALIASES = {
    "hostname": ("hostname", "computer_name", "host"),
    "username": ("username", "user", "account_name"),
    "path": ("path", "filename", "file_path", "display_name"),
    "url": ("url", "uri", "request_url"),
    "sha256_hash": ("sha256_hash", "sha256", "hash"),
    "process_id": ("process_id", "pid"),
    "parent_process_id": ("parent_process_id", "ppid"),
}


def _first(record: dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if record.get(key) not in (None, ""):
            return record[key]
    return None


def _timestamp_confidence(record: dict[str, Any], timestamp_present: bool) -> float:
    if not timestamp_present:
        return 0.0
    semantics = str(record.get("timestamp_desc") or record.get("timestamp_description") or "").lower()
    if "access" in semantics:
        return 0.45
    if any(word in semantics for word in ("creation", "written", "recorded", "logged")):
        return 0.85
    return 0.7


def normalize_record(record: dict[str, Any], sequence: int = 0) -> EvidenceEvent:
    timestamp = parse_timestamp(_first(record, ("datetime", "timestamp", "date_time", "time")))
    source = str(_first(record, ("source_long", "source", "data_type")) or "unknown")
    event_type = str(_first(record, ("event_type", "timestamp_desc", "data_type")) or "event")
    message = str(_first(record, ("message", "description", "text")) or "")
    parser = str(_first(record, ("parser", "parser_name")) or source)
    fields = {name: _first(record, aliases) for name, aliases in FIELD_ALIASES.items()}
    identity = record.get("uuid") or record.get("event_identifier") or stable_id(
        "event", timestamp.isoformat() if timestamp else "", source, event_type, message, sequence
    )
    return EvidenceEvent(
        id=str(identity), timestamp=timestamp, event_type=event_type, source=source,
        message=message, parser=parser,
        timestamp_confidence=_timestamp_confidence(record, timestamp is not None),
        raw=record, **{key: str(value) if value is not None else None for key, value in fields.items()}
    )


def _records_from_document(document: Any) -> Iterator[dict[str, Any]]:
    if isinstance(document, dict):
        events = document.get("events")
        if isinstance(events, list):
            yield from (item for item in events if isinstance(item, dict))
        else:
            yield document
    elif isinstance(document, list):
        yield from (item for item in document if isinstance(item, dict))


def read_events(path: str | Path) -> list[EvidenceEvent]:
    source_path = Path(path)
    events: list[EvidenceEvent] = []
    with source_path.open("r", encoding="utf-8-sig") as stream:
        first = stream.read(1)
        stream.seek(0)
        if first in "[":
            records = _records_from_document(json.load(stream))
        else:
            def lines() -> Iterator[dict[str, Any]]:
                for line_number, line in enumerate(stream, 1):
                    if not line.strip():
                        continue
                    try:
                        value = json.loads(line)
                    except json.JSONDecodeError as error:
                        raise ValueError(f"Invalid JSON on line {line_number}: {error.msg}") from error
                    yield from _records_from_document(value)
            records = lines()
        for sequence, record in enumerate(records):
            events.append(normalize_record(record, sequence))
    return sorted(events, key=lambda event: (event.timestamp is None, event.timestamp, event.id))

