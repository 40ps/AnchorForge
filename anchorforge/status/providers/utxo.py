"""UTXO status provider."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from anchorforge.status.context import StatusContext
from anchorforge.status.models import StatusResult, StatusWarning
from anchorforge.status.readers import read_json_file
from anchorforge.status.resolvers import select_local_json_source


DUST_LIMIT_SATOSHIS = 546
DEFAULT_LAST_COUNT = 5


def get_utxo_status(
    context: StatusContext,
    detail: str,
    next_count: int | None = None,
    min_value: int | None = None,
    max_value: int | None = None,
) -> StatusResult:
    warnings = list(context.warnings)
    utxo_path, source_warnings = select_local_json_source(
        "UTXO store",
        context.default_utxo_store_path,
        context.base_dir,
        (f"cache/**/utxo_store_{context.effective_network}_*.json",),
    )
    warnings.extend(source_warnings)
    used_path, source_warnings = select_local_json_source(
        "used UTXO store",
        context.default_used_utxo_store_path,
        context.base_dir,
        (f"cache/**/used_utxo_store_{context.effective_network}_*.json",),
    )
    warnings.extend(source_warnings)

    utxo_store, store_warnings = _read_optional_dict(utxo_path, "UTXO store")
    warnings.extend(store_warnings)
    used_store, used_warnings = _read_optional_dict(used_path, "used UTXO store")
    warnings.extend(used_warnings)

    active_utxos = _extract_utxos(utxo_store, "utxos")
    used_utxos = _extract_utxos(used_store, "used_utxos")
    filtered_utxos = _filter_utxos(active_utxos, min_value, max_value)
    preview_count = _bounded_count(next_count) if next_count is not None else 0

    return StatusResult(
        meta={"command": "utxo"},
        data={
            "detail": detail,
            "paths": {
                "utxo_store": _path_to_str(utxo_path),
                "used_utxo_store": _path_to_str(used_path),
            },
            "summary": _summary(active_utxos),
            "used_summary": _summary(used_utxos),
            "last_created": _safe_utxos(_newest_first(active_utxos)[:DEFAULT_LAST_COUNT]),
            "last_used": _safe_utxos(_newest_first(used_utxos)[:DEFAULT_LAST_COUNT]),
            "selection": {
                "min_value": min_value,
                "max_value": max_value,
                "candidate_count": len(filtered_utxos),
                "next_count": preview_count,
                "next": _safe_utxos(filtered_utxos[:preview_count]),
            },
        },
        warnings=warnings,
    )


def _read_optional_dict(path: Path | None, label: str) -> tuple[dict[str, Any] | None, list[StatusWarning]]:
    if path is None:
        return None, [StatusWarning("WARNING", f"{label} is ambiguous or unavailable", label)]
    data, warnings = read_json_file(path, dict)
    return data if isinstance(data, dict) else None, warnings


def _extract_utxos(store: object, key: str) -> list[dict[str, Any]]:
    if not isinstance(store, dict):
        return []
    utxos = store.get(key, [])
    if not isinstance(utxos, list):
        return []
    return [utxo for utxo in utxos if isinstance(utxo, dict)]


def _summary(utxos: list[dict[str, Any]]) -> dict[str, int | None]:
    values = [_utxo_value(utxo) for utxo in utxos]
    values = [value for value in values if value is not None]
    return {
        "count": len(values),
        "total_satoshis": sum(values),
        "min_satoshis": min(values) if values else None,
        "max_satoshis": max(values) if values else None,
        "dust_count": sum(1 for value in values if value < DUST_LIMIT_SATOSHIS),
    }


def _filter_utxos(
    utxos: list[dict[str, Any]],
    min_value: int | None,
    max_value: int | None,
) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    for utxo in _newest_first(utxos):
        value = _utxo_value(utxo)
        if value is None:
            continue
        if min_value is not None and value < min_value:
            continue
        if max_value is not None and value > max_value:
            continue
        filtered.append(utxo)
    return filtered


def _newest_first(utxos: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        utxos,
        key=lambda utxo: (
            _safe_str(utxo.get("timestamp")) or "",
            _safe_str(utxo.get("txid")) or "",
            _safe_int(utxo.get("vout")) or -1,
        ),
        reverse=True,
    )


def _safe_utxos(utxos: list[dict[str, Any]]) -> list[dict[str, Any]]:
    safe: list[dict[str, Any]] = []
    for utxo in utxos:
        safe.append(
            {
                "txid": _safe_str(utxo.get("txid")),
                "vout": _safe_int(utxo.get("vout")),
                "satoshis": _utxo_value(utxo),
                "height": _safe_int(utxo.get("height")),
                "timestamp": _safe_str(utxo.get("timestamp")),
                "used": _safe_bool(utxo.get("used")),
                "outpoint": _outpoint(utxo),
            }
        )
    return safe


def _outpoint(utxo: dict[str, Any]) -> str | None:
    txid = _safe_str(utxo.get("txid"))
    vout = _safe_int(utxo.get("vout"))
    if txid is None or vout is None:
        return None
    return f"{txid}:{vout}"


def _utxo_value(utxo: dict[str, Any]) -> int | None:
    value = utxo.get("satoshis", utxo.get("value"))
    return _safe_int(value)


def _safe_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_bool(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _safe_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _bounded_count(value: int) -> int:
    return max(0, min(value, 100))


def _path_to_str(path: Path | None) -> str | None:
    return str(path) if path else None
