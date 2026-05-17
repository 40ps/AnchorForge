"""Transaction status provider."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from anchorforge.status.context import StatusContext
from anchorforge.status.models import StatusResult, StatusWarning
from anchorforge.status.readers import read_json_file
from anchorforge.status.resolvers import select_local_json_source


DEFAULT_LAST_COUNT = 5


def get_tx_status(context: StatusContext, detail: str) -> StatusResult:
    warnings = list(context.warnings)
    tx_path, source_warnings = select_local_json_source(
        "TX store",
        context.default_tx_store_path,
        context.base_dir,
        (f"database/**/tx_store_{context.effective_network}_*.json",),
    )
    warnings.extend(source_warnings)

    tx_store, store_warnings = _read_optional_dict(tx_path, "TX store")
    warnings.extend(store_warnings)
    transactions = _extract_transactions(tx_store)
    summaries = [_safe_tx_summary(tx) for tx in _newest_first(transactions)]

    return StatusResult(
        meta={"command": "tx"},
        data={
            "detail": detail,
            "paths": {"tx_store": _path_to_str(tx_path)},
            "summary": _store_summary(tx_store, transactions),
            "last_txids": [item["txid"] for item in summaries[:DEFAULT_LAST_COUNT] if item["txid"]],
            "transactions": summaries if detail == "full" else summaries[:DEFAULT_LAST_COUNT],
        },
        warnings=warnings,
    )


def _read_optional_dict(path: Path | None, label: str) -> tuple[dict[str, Any] | None, list[StatusWarning]]:
    if path is None:
        return None, [StatusWarning("WARNING", f"{label} is ambiguous or unavailable", label)]
    data, warnings = read_json_file(path, dict)
    return data if isinstance(data, dict) else None, warnings


def _extract_transactions(store: object) -> list[dict[str, Any]]:
    if not isinstance(store, dict):
        return []
    transactions = store.get("transactions", [])
    if not isinstance(transactions, list):
        return []
    return [tx for tx in transactions if isinstance(tx, dict)]


def _store_summary(store: object, transactions: list[dict[str, Any]]) -> dict[str, int | str | None]:
    last = _last_transaction(transactions)
    return {
        "count": len(transactions),
        "store_address": _safe_str(store.get("address")) if isinstance(store, dict) else None,
        "store_network": _safe_str(store.get("network")) if isinstance(store, dict) else None,
        "last_txid": _safe_str(last.get("txid")) if last else None,
        "last_timestamp": _safe_str(last.get("timestamp")) if last else None,
    }


def _newest_first(transactions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        transactions,
        key=lambda tx: (
            _safe_str(tx.get("timestamp")) or "",
            _safe_str(tx.get("txid")) or "",
        ),
        reverse=True,
    )


def _last_transaction(transactions: list[dict[str, Any]]) -> dict[str, Any] | None:
    ordered = _newest_first(transactions)
    return ordered[0] if ordered else None


def _safe_tx_summary(tx: dict[str, Any]) -> dict[str, int | str | bool | None]:
    rawtx = _safe_str(tx.get("rawtx"))
    return {
        "txid": _safe_str(tx.get("txid")),
        "timestamp": _safe_str(tx.get("timestamp")),
        "has_rawtx": bool(rawtx),
        "rawtx_hex_chars": len(rawtx) if rawtx else 0,
        "rawtx_bytes": len(rawtx) // 2 if rawtx and _is_even_hex(rawtx) else None,
    }


def _is_even_hex(value: str) -> bool:
    if len(value) % 2:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _safe_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _path_to_str(path: Path | None) -> str | None:
    return str(path) if path else None
