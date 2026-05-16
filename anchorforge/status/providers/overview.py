"""Overview status provider."""

from __future__ import annotations

from anchorforge.status.context import StatusContext
from anchorforge.status.models import StatusResult, StatusWarning
from anchorforge.status.readers import read_json_file


def get_overview_status(context: StatusContext, detail: str) -> StatusResult:
    warnings = list(context.warnings)
    audit_log, audit_warnings = read_json_file(context.audit_log_path, list)
    tx_store, tx_warnings = read_json_file(context.default_tx_store_path, dict)
    utxo_store, utxo_warnings = read_json_file(context.default_utxo_store_path, dict)
    headers, header_warnings = read_json_file(context.header_cache_path, dict)
    warnings.extend(audit_warnings)
    warnings.extend(tx_warnings)
    warnings.extend(utxo_warnings)
    warnings.extend(header_warnings)
    warnings.append(
        StatusWarning(
            "WARNING",
            "af_status skeleton architecture is installed; detailed providers are not implemented yet",
            "overview",
        )
    )

    data = {
        "config_network": context.config_network,
        "cli_network_override": context.cli_network_override,
        "effective_network": context.effective_network,
        "config_source": str(context.config_source),
        "bank_address": context.bank_address,
        "working_address": context.worker_address,
        "utxo_summary": _utxo_summary(utxo_store),
        "tx_count": _tx_count(tx_store),
        "integrity_record_count": len(audit_log) if isinstance(audit_log, list) else 0,
        "header_count": len(headers) if isinstance(headers, dict) else 0,
        "detail": detail,
    }
    return StatusResult(meta={"command": "overview"}, data=data, warnings=warnings)


def _utxo_summary(store: object) -> dict[str, int]:
    if not isinstance(store, dict):
        return {"count": 0, "total_satoshis": 0, "dust_count": 0}
    utxos = store.get("utxos", [])
    if not isinstance(utxos, list):
        return {"count": 0, "total_satoshis": 0, "dust_count": 0}
    values = [int(item.get("satoshis", item.get("value", 0))) for item in utxos if isinstance(item, dict)]
    return {
        "count": len(values),
        "total_satoshis": sum(values),
        "dust_count": sum(1 for value in values if value < 546),
    }


def _tx_count(store: object) -> int:
    if not isinstance(store, dict):
        return 0
    transactions = store.get("transactions", [])
    return len(transactions) if isinstance(transactions, list) else 0
