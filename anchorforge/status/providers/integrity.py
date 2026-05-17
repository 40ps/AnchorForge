"""Integrity/audit-log status provider."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from anchorforge.status.context import StatusContext
from anchorforge.status.models import StatusResult, StatusWarning
from anchorforge.status.readers import read_json_file
from anchorforge.status.resolvers import select_local_json_source


DEFAULT_LAST_COUNT = 5


def get_integrity_status(
    context: StatusContext,
    detail: str,
    keyword: str | None = None,
    txid: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> StatusResult:
    warnings = list(context.warnings)
    audit_path, source_warnings = select_local_json_source(
        "audit log",
        context.audit_log_path,
        context.base_dir,
        (f"output/audit_log_{context.effective_network}.json",),
    )
    warnings.extend(source_warnings)

    records, read_warnings = _read_optional_list(audit_path, "audit log")
    warnings.extend(read_warnings)
    valid_records = _extract_records(records)
    filtered_records, filter_warnings = _filter_records(
        valid_records,
        keyword=keyword,
        txid=txid,
        date_from=date_from,
        date_to=date_to,
    )
    warnings.extend(filter_warnings)
    ordered_records = _newest_first(filtered_records)
    last_record = _last_record(valid_records)

    return StatusResult(
        meta={"command": "integrity"},
        data={
            "detail": detail,
            "paths": {"audit_log": _path_to_str(audit_path)},
            "filters": {
                "keyword": keyword,
                "txid": txid,
                "date_from": date_from,
                "date_to": date_to,
            },
            "summary": {
                "record_count": len(valid_records),
                "filtered_count": len(filtered_records),
                "last_log_id": _safe_str(last_record.get("log_id")) if last_record else None,
                "last_timestamp": _record_timestamp_text(last_record) if last_record else None,
                "last_keyword": _safe_str(last_record.get("keyword")) if last_record else None,
                "last_txid": _record_txid(last_record) if last_record else None,
            },
            "last_records": _safe_records(
                ordered_records if detail == "full" else ordered_records[:DEFAULT_LAST_COUNT]
            ),
        },
        warnings=warnings,
    )


def _read_optional_list(path: Path | None, label: str) -> tuple[list[Any] | None, list[StatusWarning]]:
    if path is None:
        return None, [StatusWarning("WARNING", f"{label} is ambiguous or unavailable", label)]
    data, warnings = read_json_file(path, list)
    return data if isinstance(data, list) else None, warnings


def _extract_records(records: object) -> list[dict[str, Any]]:
    if not isinstance(records, list):
        return []
    return [record for record in records if isinstance(record, dict)]


def _filter_records(
    records: list[dict[str, Any]],
    keyword: str | None,
    txid: str | None,
    date_from: str | None,
    date_to: str | None,
) -> tuple[list[dict[str, Any]], list[StatusWarning]]:
    warnings: list[StatusWarning] = []
    start, start_warning = _parse_filter_date(date_from, "date-from")
    end, end_warning = _parse_filter_date(date_to, "date-to")
    warnings.extend(start_warning)
    warnings.extend(end_warning)

    filtered: list[dict[str, Any]] = []
    for record in records:
        if keyword and keyword.lower() not in (_safe_str(record.get("keyword")) or "").lower():
            continue
        if txid and txid != _record_txid(record):
            continue
        if start or end:
            timestamp = _record_datetime(record)
            if timestamp is None:
                warnings.append(
                    StatusWarning(
                        "WARNING",
                        "Record timestamp could not be parsed for date filtering",
                        _safe_str(record.get("log_id")) or "",
                    )
                )
                continue
            if start and timestamp < start:
                continue
            if end and timestamp > end:
                continue
        filtered.append(record)
    return filtered, warnings


def _parse_filter_date(value: str | None, label: str) -> tuple[datetime | None, list[StatusWarning]]:
    if not value:
        return None, []
    parsed = _parse_datetime(value)
    if parsed is None:
        return None, [StatusWarning("WARNING", f"{label} could not be parsed; filter ignored", value)]
    return parsed, []


def _newest_first(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        records,
        key=lambda record: (
            _record_timestamp_text(record) or "",
            _safe_str(record.get("log_id")) or "",
        ),
        reverse=True,
    )


def _last_record(records: list[dict[str, Any]]) -> dict[str, Any] | None:
    ordered = _newest_first(records)
    return ordered[0] if ordered else None


def _safe_records(records: list[dict[str, Any]]) -> list[dict[str, str | None]]:
    return [
        {
            "log_id": _safe_str(record.get("log_id")),
            "timestamp": _record_timestamp_text(record),
            "keyword": _safe_str(record.get("keyword")),
            "txid": _record_txid(record),
            "status": _record_status(record),
        }
        for record in records
    ]


def _record_txid(record: dict[str, Any]) -> str | None:
    blockchain_record = record.get("blockchain_record")
    if isinstance(blockchain_record, dict):
        return _safe_str(blockchain_record.get("txid"))
    return None


def _record_status(record: dict[str, Any]) -> str | None:
    blockchain_record = record.get("blockchain_record")
    if isinstance(blockchain_record, dict):
        return _safe_str(blockchain_record.get("status"))
    return None


def _record_timestamp_text(record: dict[str, Any] | None) -> str | None:
    if not isinstance(record, dict):
        return None
    return (
        _safe_str(record.get("timestamp_logged_local"))
        or _safe_str(record.get("timestamp"))
        or _safe_str(record.get("created_at"))
    )


def _record_datetime(record: dict[str, Any]) -> datetime | None:
    return _parse_datetime(_record_timestamp_text(record))


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _safe_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _path_to_str(path: Path | None) -> str | None:
    return str(path) if path else None
