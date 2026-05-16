"""Read-only status file readers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from anchorforge.status.models import StatusWarning


def read_json_file(path: Path, expected_type: type) -> tuple[Any | None, list[StatusWarning]]:
    if not path.exists():
        return None, [StatusWarning("WARNING", "Local data file is missing", str(path))]
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        return None, [StatusWarning("WARNING", f"Local data file is malformed JSON: {exc}", str(path))]
    except OSError as exc:
        return None, [StatusWarning("WARNING", f"Local data file could not be read: {exc}", str(path))]
    if not isinstance(data, expected_type):
        return None, [
            StatusWarning(
                "WARNING",
                f"Local data file has unexpected top-level type {type(data).__name__}",
                str(path),
            )
        ]
    return data, []
