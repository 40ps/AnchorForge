"""Read-only status resolution helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from anchorforge.status.models import StatusWarning


def effective_network_name(config_network: str, cli_network_override: str | None) -> str:
    return cli_network_override or config_network


def path_from_config(config: Any, attr: str) -> Path:
    return Path(getattr(config, attr))


def select_local_json_source(
    label: str,
    configured_path: Path,
    base_dir: Path,
    patterns: tuple[str, ...],
) -> tuple[Path | None, list[StatusWarning]]:
    """Select one local JSON source without creating, repairing, or merging files."""
    if configured_path.exists():
        return configured_path, []

    candidates = _discover_existing_files(base_dir, patterns)
    if not candidates:
        return configured_path, []
    if len(candidates) == 1:
        return candidates[0], []

    candidate_list = ", ".join(str(path) for path in candidates)
    return None, [
        StatusWarning(
            "WARNING",
            f"Multiple {label} candidates found; no automatic merge performed",
            candidate_list,
        )
    ]


def _discover_existing_files(base_dir: Path, patterns: tuple[str, ...]) -> list[Path]:
    discovered: dict[str, Path] = {}
    for pattern in patterns:
        for path in base_dir.glob(pattern):
            if path.is_file() and not path.name.endswith(".sim.json"):
                discovered[str(path.resolve())] = path
    return [discovered[key] for key in sorted(discovered)]
