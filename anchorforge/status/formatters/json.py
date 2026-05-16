"""JSON status formatter."""

from __future__ import annotations

import json

from anchorforge.status.models import StatusResult


def format_json(result: StatusResult) -> str:
    return json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":"))
