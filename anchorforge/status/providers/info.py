"""Local object inspection provider."""

from __future__ import annotations

import hashlib
from typing import Any

from anchorforge.status.context import StatusContext
from anchorforge.status.models import StatusResult, StatusWarning
from anchorforge.status.providers.integrity import get_integrity_status
from anchorforge.status.providers.tx import get_tx_status
from anchorforge.status.providers.utxo import get_utxo_status


def get_info_status(context: StatusContext, detail: str, args: dict[str, Any]) -> StatusResult:
    info_type = str(args.get("type") or "")
    if info_type == "tx":
        return _tx_info(context, detail, args)
    if info_type == "ir":
        return _ir_info(context, detail, args)
    if info_type == "utxo":
        return _utxo_info(context, detail, args)
    return StatusResult(
        meta={"command": "info", "type": info_type},
        data={"detail": detail, "query": _safe_query(args)},
        warnings=[*context.warnings, StatusWarning("ERROR", "Unsupported info type", info_type)],
    )


def _tx_info(context: StatusContext, detail: str, args: dict[str, Any]) -> StatusResult:
    txid = _safe_str(args.get("txid"))
    rawtx = _safe_str(args.get("rawtx"))
    warnings: list[StatusWarning] = []
    rawtx_summary: dict[str, Any] | None = None
    if rawtx:
        rawtx_summary = _rawtx_summary(rawtx)
        warning = rawtx_summary.pop("_warning", None)
        if isinstance(warning, StatusWarning):
            warnings.append(warning)
        txid = _safe_str(rawtx_summary.get("computed_txid"))

    provider_result = get_tx_status(context, "full")
    warnings = [*provider_result.warnings, *warnings]
    transaction = _find_by_key(provider_result.data.get("transactions"), "txid", txid)
    if transaction is None:
        warnings.append(StatusWarning("WARNING", "Transaction was not found in local TX store", txid or ""))

    return StatusResult(
        meta={"command": "info", "type": "tx"},
        data={
            "detail": detail,
            "query": _safe_query(args),
            "rawtx_summary": rawtx_summary,
            "transaction": transaction,
        },
        warnings=warnings,
    )


def _ir_info(context: StatusContext, detail: str, args: dict[str, Any]) -> StatusResult:
    provider_result = get_integrity_status(
        context,
        "full",
        keyword=_safe_str(args.get("keyword")),
        txid=_safe_str(args.get("txid")),
        date_from=_safe_str(args.get("date_from")),
        date_to=_safe_str(args.get("date_to")),
    )
    log_id = _safe_str(args.get("id"))
    records = _list_items(provider_result.data.get("last_records"))
    if log_id:
        records = [record for record in records if isinstance(record, dict) and record.get("log_id") == log_id]

    warnings = list(provider_result.warnings)
    if not records:
        warnings.append(StatusWarning("WARNING", "Integrity record was not found in local audit log", log_id or ""))

    return StatusResult(
        meta={"command": "info", "type": "ir"},
        data={
            "detail": detail,
            "query": _safe_query(args),
            "count": len(records),
            "records": records,
        },
        warnings=warnings,
    )


def _utxo_info(context: StatusContext, detail: str, args: dict[str, Any]) -> StatusResult:
    outpoint = _safe_str(args.get("outpoint"))
    provider_result = get_utxo_status(context, "full")
    candidates = [
        *_list_items(provider_result.data.get("last_created")),
        *_list_items(provider_result.data.get("last_used")),
    ]
    matches = [
        item for item in candidates if isinstance(item, dict) and item.get("outpoint") == outpoint
    ]
    warnings = list(provider_result.warnings)
    if not matches:
        warnings.append(StatusWarning("WARNING", "UTXO was not found in local UTXO stores", outpoint or ""))

    return StatusResult(
        meta={"command": "info", "type": "utxo"},
        data={
            "detail": detail,
            "query": _safe_query(args),
            "count": len(matches),
            "utxos": matches,
        },
        warnings=warnings,
    )


def _rawtx_summary(rawtx: str) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "hex_chars": len(rawtx),
        "hex_valid": False,
        "byte_length": None,
        "computed_txid": None,
    }
    if len(rawtx) % 2:
        summary["_warning"] = StatusWarning("WARNING", "Raw transaction hex has odd length", "rawtx")
        return summary
    try:
        raw_bytes = bytes.fromhex(rawtx)
    except ValueError:
        summary["_warning"] = StatusWarning("WARNING", "Raw transaction is not valid hex", "rawtx")
        return summary
    summary["hex_valid"] = True
    summary["byte_length"] = len(raw_bytes)
    summary["computed_txid"] = hashlib.sha256(hashlib.sha256(raw_bytes).digest()).digest()[::-1].hex()
    return summary


def _find_by_key(items: object, key: str, value: str | None) -> dict[str, Any] | None:
    if not value:
        return None
    for item in _list_items(items):
        if isinstance(item, dict) and item.get(key) == value:
            return item
    return None


def _safe_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _list_items(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _safe_query(args: dict[str, Any]) -> dict[str, Any]:
    allowed = {"txid", "rawtx", "id", "keyword", "date_from", "date_to", "outpoint"}
    return {key: value for key, value in args.items() if key in allowed and value is not None}
