"""UTXO status provider skeleton."""

from __future__ import annotations

from anchorforge.status.context import StatusContext
from anchorforge.status.models import StatusResult, StatusWarning


def get_utxo_status(context: StatusContext, detail: str) -> StatusResult:
    return StatusResult(
        meta={"command": "utxo"},
        data={"detail": detail, "path": str(context.default_utxo_store_path)},
        warnings=[*context.warnings, StatusWarning("WARNING", "UTXO provider skeleton only", "utxo")],
    )
