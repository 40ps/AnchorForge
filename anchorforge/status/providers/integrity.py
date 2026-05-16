"""Integrity status provider skeleton."""

from __future__ import annotations

from anchorforge.status.context import StatusContext
from anchorforge.status.models import StatusResult, StatusWarning


def get_integrity_status(context: StatusContext, detail: str) -> StatusResult:
    return StatusResult(
        meta={"command": "integrity"},
        data={"detail": detail, "path": str(context.audit_log_path)},
        warnings=[
            *context.warnings,
            StatusWarning("WARNING", "Integrity provider skeleton only", "integrity"),
        ],
    )
