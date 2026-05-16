"""Transaction status provider skeleton."""

from __future__ import annotations

from anchorforge.status.context import StatusContext
from anchorforge.status.models import StatusResult, StatusWarning


def get_tx_status(context: StatusContext, detail: str) -> StatusResult:
    return StatusResult(
        meta={"command": "tx"},
        data={"detail": detail, "path": str(context.default_tx_store_path)},
        warnings=[*context.warnings, StatusWarning("WARNING", "TX provider skeleton only", "tx")],
    )
