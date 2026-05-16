"""Last-query provider skeleton."""

from __future__ import annotations

from anchorforge.status.context import StatusContext
from anchorforge.status.models import StatusResult, StatusWarning


def get_last_status(context: StatusContext, detail: str, item_type: str, n: int) -> StatusResult:
    count = max(0, min(n, 100))
    return StatusResult(
        meta={"command": "last", "type": item_type},
        data={"detail": detail, "limit": count, "items": []},
        warnings=[*context.warnings, StatusWarning("WARNING", "Last provider skeleton only", item_type)],
    )
