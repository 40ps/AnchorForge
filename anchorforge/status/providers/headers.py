"""Header status provider skeleton."""

from __future__ import annotations

from anchorforge.status.context import StatusContext
from anchorforge.status.models import StatusResult, StatusWarning


def get_headers_status(context: StatusContext, detail: str) -> StatusResult:
    return StatusResult(
        meta={"command": "headers"},
        data={"detail": detail, "path": str(context.header_cache_path)},
        warnings=[
            *context.warnings,
            StatusWarning("WARNING", "Headers provider skeleton only", "headers"),
        ],
    )
