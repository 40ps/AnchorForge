"""Overview status provider."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from anchorforge.status.context import StatusContext
from anchorforge.status.models import StatusResult, StatusWarning
from anchorforge.status.readers import read_json_file
from anchorforge.status.resolvers import select_local_json_source


TOOL_VERSION = "0.1"
DUST_LIMIT_SATOSHIS = 546


def get_overview_status(context: StatusContext, detail: str) -> StatusResult:
    warnings = list(context.warnings)
    utxo_path, source_warnings = select_local_json_source(
        "UTXO store",
        context.default_utxo_store_path,
        context.base_dir,
        (f"cache/**/utxo_store_{context.effective_network}_*.json",),
    )
    warnings.extend(source_warnings)
    tx_path, source_warnings = select_local_json_source(
        "TX store",
        context.default_tx_store_path,
        context.base_dir,
        (f"database/**/tx_store_{context.effective_network}_*.json",),
    )
    warnings.extend(source_warnings)
    audit_path, source_warnings = select_local_json_source(
        "audit log",
        context.audit_log_path,
        context.base_dir,
        (f"output/audit_log_{context.effective_network}.json",),
    )
    warnings.extend(source_warnings)
    header_path, source_warnings = select_local_json_source(
        "header cache",
        context.header_cache_path,
        context.base_dir,
        (f"cache/**/block_headers_{context.effective_network}.json",),
    )
    warnings.extend(source_warnings)

    utxo_store, utxo_warnings = _read_optional_dict(utxo_path, "UTXO store")
    tx_store, tx_warnings = _read_optional_dict(tx_path, "TX store")
    audit_log, audit_warnings = _read_optional_list(audit_path, "audit log")
    headers, header_warnings = _read_optional_dict(header_path, "header cache")
    warnings.extend(utxo_warnings)
    warnings.extend(tx_warnings)
    warnings.extend(audit_warnings)
    warnings.extend(header_warnings)

    data = {
        "tool_version": TOOL_VERSION,
        "anchorforge_version": _anchorforge_version(),
        "config_network": context.config_network,
        "cli_network_override": context.cli_network_override,
        "effective_network": context.effective_network,
        "config_source": str(context.config_source),
        "bank_address": context.bank_address,
        "working_address": context.worker_address,
        "utxo_summary": _utxo_summary(utxo_store),
        "last_local_txid": _last_txid(tx_store),
        "tx_summary": _tx_summary(tx_store),
        "integrity_summary": _integrity_summary(audit_log),
        "header_readiness": _header_readiness(headers, audit_log),
        "critical_warnings": [warning.message for warning in warnings if warning.level == "CRITICAL"],
        "paths": {
            "utxo_store": _path_to_str(utxo_path),
            "tx_store": _path_to_str(tx_path),
            "audit_log": _path_to_str(audit_path),
            "header_cache": _path_to_str(header_path),
        },
        "help_hint": "Run af_status.py --help for commands.",
        "detail": detail,
    }
    return StatusResult(meta={"command": "overview"}, data=data, warnings=warnings)


def _read_optional_dict(path: Path | None, label: str) -> tuple[dict[str, Any] | None, list[StatusWarning]]:
    if path is None:
        return None, [StatusWarning("WARNING", f"{label} is ambiguous or unavailable", label)]
    data, warnings = read_json_file(path, dict)
    return data if isinstance(data, dict) else None, warnings


def _read_optional_list(path: Path | None, label: str) -> tuple[list[Any] | None, list[StatusWarning]]:
    if path is None:
        return None, [StatusWarning("WARNING", f"{label} is ambiguous or unavailable", label)]
    data, warnings = read_json_file(path, list)
    return data if isinstance(data, list) else None, warnings


def _utxo_summary(store: object) -> dict[str, int | None]:
    empty = {
        "count": 0,
        "total_satoshis": 0,
        "min_satoshis": None,
        "max_satoshis": None,
        "dust_count": 0,
    }
    if not isinstance(store, dict):
        return empty
    utxos = store.get("utxos", [])
    if not isinstance(utxos, list):
        return empty
    values = [_utxo_value(item) for item in utxos if isinstance(item, dict)]
    values = [value for value in values if value is not None]
    return {
        "count": len(values),
        "total_satoshis": sum(values),
        "min_satoshis": min(values) if values else None,
        "max_satoshis": max(values) if values else None,
        "dust_count": sum(1 for value in values if value < DUST_LIMIT_SATOSHIS),
    }


def _utxo_value(item: dict[str, Any]) -> int | None:
    value = item.get("satoshis", item.get("value"))
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _tx_summary(store: object) -> dict[str, int | str | None]:
    if not isinstance(store, dict):
        return {"count": 0, "last_txid": None, "last_timestamp": None}
    transactions = store.get("transactions", [])
    if not isinstance(transactions, list):
        return {"count": 0, "last_txid": None, "last_timestamp": None}
    valid_transactions = [item for item in transactions if isinstance(item, dict)]
    last = _last_dict(valid_transactions)
    return {
        "count": len(valid_transactions),
        "last_txid": _safe_str(last.get("txid")) if last else None,
        "last_timestamp": _safe_str(last.get("timestamp")) if last else None,
    }


def _last_txid(store: object) -> str | None:
    return _tx_summary(store)["last_txid"]


def _integrity_summary(records: object) -> dict[str, int | str | None]:
    if not isinstance(records, list):
        return {"record_count": 0, "last_log_id": None, "timestamp": None, "keyword": None}
    valid_records = [record for record in records if isinstance(record, dict)]
    last = _last_dict(valid_records)
    return {
        "record_count": len(valid_records),
        "last_log_id": _safe_str(last.get("log_id")) if last else None,
        "timestamp": _safe_str(last.get("timestamp_logged_local")) if last else None,
        "keyword": _safe_str(last.get("keyword")) if last else None,
    }


def _header_readiness(headers: object, records: object) -> dict[str, int | str | list[str]]:
    if not isinstance(headers, dict) or not headers:
        return {"status": "missing", "header_count": 0, "missing_block_hashes": []}

    required = _confirmed_block_hashes(records)
    available = _available_block_hashes(headers)
    missing = sorted(required - available)
    return {
        "status": "ready" if not missing else "incomplete",
        "header_count": len(headers),
        "missing_block_hashes": missing,
    }


def _confirmed_block_hashes(records: object) -> set[str]:
    if not isinstance(records, list):
        return set()
    hashes: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        blockchain_record = record.get("blockchain_record")
        if not isinstance(blockchain_record, dict):
            continue
        status = str(blockchain_record.get("status", "")).lower()
        block_hash = blockchain_record.get("block_hash") or blockchain_record.get("blockhash")
        if status == "confirmed" and isinstance(block_hash, str) and block_hash:
            hashes.add(block_hash)
    return hashes


def _available_block_hashes(headers: dict[str, Any]) -> set[str]:
    hashes: set[str] = set()
    for key, value in headers.items():
        if isinstance(key, str):
            hashes.add(key)
        if isinstance(value, dict):
            block_hash = value.get("hash") or value.get("block_hash") or value.get("blockhash")
            if isinstance(block_hash, str):
                hashes.add(block_hash)
    return hashes


def _last_dict(items: list[dict[str, Any]]) -> dict[str, Any] | None:
    return items[-1] if items else None


def _safe_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _path_to_str(path: Path | None) -> str | None:
    return str(path) if path else None


def _anchorforge_version() -> str:
    try:
        return version("anchorforge")
    except PackageNotFoundError:
        return "unknown"
