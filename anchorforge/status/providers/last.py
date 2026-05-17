"""Last-query provider."""

from __future__ import annotations

from anchorforge.status.context import StatusContext
from anchorforge.status.models import StatusResult, StatusWarning
from anchorforge.status.providers.headers import get_headers_status
from anchorforge.status.providers.integrity import get_integrity_status
from anchorforge.status.providers.overview import get_overview_status
from anchorforge.status.providers.tx import get_tx_status
from anchorforge.status.providers.utxo import get_utxo_status


MAX_LAST_COUNT = 100


def get_last_status(context: StatusContext, detail: str, item_type: str, n: int) -> StatusResult:
    count = min(n, MAX_LAST_COUNT)
    provider_result = _provider_result(context, item_type)
    items = _items_for_type(provider_result, item_type, count)
    return StatusResult(
        meta={"command": "last", "type": item_type},
        data={
            "detail": detail,
            "requested": n,
            "limit": count,
            "items": items,
        },
        warnings=list(provider_result.warnings),
    )


def _provider_result(context: StatusContext, item_type: str) -> StatusResult:
    if item_type in {"txid", "tx"}:
        return get_tx_status(context, "full")
    if item_type in {"utxo-created", "utxo-used"}:
        return get_utxo_status(context, "full")
    if item_type == "ir":
        return get_integrity_status(context, "full")
    if item_type == "warnings":
        return _warnings_result(context)
    return StatusResult(
        meta={"command": "last", "type": item_type},
        data={},
        warnings=[*context.warnings, StatusWarning("ERROR", "Unsupported last type", item_type)],
    )


def _items_for_type(result: StatusResult, item_type: str, count: int) -> list[object]:
    data = result.data
    if item_type == "txid":
        return _txids_from_transactions(data.get("transactions", []))[:count]
    if item_type == "tx":
        return _list_items(data.get("transactions", []))[:count]
    if item_type == "ir":
        return _list_items(data.get("last_records", []))[:count]
    if item_type == "utxo-created":
        return _list_items(data.get("last_created", []))[:count]
    if item_type == "utxo-used":
        return _list_items(data.get("last_used", []))[:count]
    if item_type == "warnings":
        return [warning.to_dict() for warning in result.warnings[:count]]
    return []


def _txids_from_transactions(items: object) -> list[str]:
    txids: list[str] = []
    for item in _list_items(items):
        if isinstance(item, dict):
            txid = item.get("txid")
            if isinstance(txid, str):
                txids.append(txid)
    return txids


def _list_items(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _warnings_result(context: StatusContext) -> StatusResult:
    warnings: list[StatusWarning] = []
    for result in (
        get_overview_status(context, "normal"),
        get_tx_status(context, "normal"),
        get_integrity_status(context, "normal"),
        get_utxo_status(context, "normal"),
        get_headers_status(context, "normal"),
    ):
        warnings.extend(result.warnings)
    return StatusResult(
        meta={"command": "last", "type": "warnings"},
        data={},
        warnings=_dedupe_warnings(warnings),
    )


def _dedupe_warnings(warnings: list[StatusWarning]) -> list[StatusWarning]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[StatusWarning] = []
    for warning in warnings:
        key = (warning.level, warning.message, warning.context)
        if key not in seen:
            seen.add(key)
            unique.append(warning)
    return unique
