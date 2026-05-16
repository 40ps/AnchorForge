"""Warnings provider skeleton."""

from __future__ import annotations

from anchorforge.status.context import StatusContext
from anchorforge.status.models import StatusResult


def get_warnings_status(context: StatusContext, detail: str) -> StatusResult:
    return StatusResult(
        meta={"command": "warnings"},
        data={"detail": detail, "warning_count": len(context.warnings)},
        warnings=list(context.warnings),
    )
