"""Info-query provider skeleton."""

from __future__ import annotations

from typing import Any

from anchorforge.status.context import StatusContext
from anchorforge.status.models import StatusResult, StatusWarning


def get_info_status(context: StatusContext, detail: str, args: dict[str, Any]) -> StatusResult:
    info_type = str(args.get("type") or "")
    return StatusResult(
        meta={"command": "info", "type": info_type},
        data={"detail": detail, "query": _safe_query(args)},
        warnings=[*context.warnings, StatusWarning("WARNING", "Info provider skeleton only", info_type)],
    )


def _safe_query(args: dict[str, Any]) -> dict[str, Any]:
    allowed = {"txid", "rawtx", "id", "keyword", "date_from", "date_to", "outpoint"}
    return {key: value for key, value in args.items() if key in allowed and value is not None}
