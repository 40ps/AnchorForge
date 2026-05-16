"""Read-only status resolution helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def effective_network_name(config_network: str, cli_network_override: str | None) -> str:
    return cli_network_override or config_network


def path_from_config(config: Any, attr: str) -> Path:
    return Path(getattr(config, attr))
