"""Status context construction.

Config is loaded only inside this module's controlled loader so JSON output can
remain clean and callers do not import AnchorForge configuration at module load.
"""

from __future__ import annotations

import contextlib
import importlib
import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from anchorforge.status.models import StatusResult, StatusWarning
from anchorforge.status.resolvers import effective_network_name, path_from_config


@dataclass(frozen=True)
class StatusContext:
    config_network: str
    cli_network_override: str | None
    effective_network: str
    config_source: Path
    base_dir: Path
    output_dir: Path
    database_dir: Path
    wallet_cache_dir: Path
    public_cache_dir: Path
    audit_log_path: Path
    header_cache_path: Path
    default_utxo_store_path: Path
    default_used_utxo_store_path: Path
    default_tx_store_path: Path
    worker_address: str | None
    bank_address: str | None
    address_utxo_store_path: Path | None = None
    address_used_utxo_store_path: Path | None = None
    address_tx_store_path: Path | None = None
    warnings: list[StatusWarning] = field(default_factory=list)


class ConfigLoadError(Exception):
    """Raised when status context construction cannot load configuration."""

    def __init__(self, message: str, diagnostics: list[StatusWarning] | None = None) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics or []

    def to_result(self) -> StatusResult:
        return StatusResult(
            meta={"command": "status"},
            data={},
            warnings=[*self.diagnostics, StatusWarning("ERROR", str(self), "configuration")],
        )


def _load_config() -> tuple[Any, list[StatusWarning]]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            module = importlib.import_module("anchorforge.config")
            config = module.Config
    except Exception as exc:
        warnings = _captured_diagnostics(stdout.getvalue(), stderr.getvalue())
        raise ConfigLoadError(str(exc), warnings) from exc
    return config, _captured_diagnostics(stdout.getvalue(), stderr.getvalue())


def _captured_diagnostics(stdout: str, stderr: str) -> list[StatusWarning]:
    warnings: list[StatusWarning] = []
    for label, text in (("stdout", stdout), ("stderr", stderr)):
        for line in text.splitlines():
            if line.strip():
                warnings.append(StatusWarning("WARNING", line.strip(), f"config {label}"))
    return warnings


def build_status_context(cli_network_override: str | None = None) -> StatusContext:
    config, warnings = _load_config()
    config_network = str(getattr(config, "ACTIVE_NETWORK_NAME", "test"))
    effective_network = effective_network_name(config_network, cli_network_override)

    output_dir = path_from_config(config, "OUTPUT_DIR")
    database_dir = path_from_config(config, "DATABASE_DIR")
    wallet_cache_dir = path_from_config(config, "WALLET_CACHE_DIR")
    public_cache_dir = path_from_config(config, "PUBLIC_CACHE_DIR")

    return StatusContext(
        config_network=config_network,
        cli_network_override=cli_network_override,
        effective_network=effective_network,
        config_source=path_from_config(config, "ENV_PATH"),
        base_dir=path_from_config(config, "BASE_DIR"),
        output_dir=output_dir,
        database_dir=database_dir,
        wallet_cache_dir=wallet_cache_dir,
        public_cache_dir=public_cache_dir,
        audit_log_path=output_dir / f"audit_log_{effective_network}.json",
        header_cache_path=public_cache_dir / f"block_headers_{effective_network}.json",
        default_utxo_store_path=wallet_cache_dir / f"utxo_store_{effective_network}.json",
        default_used_utxo_store_path=wallet_cache_dir / f"used_utxo_store_{effective_network}.json",
        default_tx_store_path=database_dir / f"tx_store_{effective_network}.json",
        worker_address=None,
        bank_address=getattr(config, "BANK_ADDRESS", None),
        warnings=warnings,
    )
