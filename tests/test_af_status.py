import json
from pathlib import Path

import pytest

import af_status
from anchorforge.config import Config
from anchorforge.status.context import StatusContext
from anchorforge.status.providers.headers import get_headers_status
from anchorforge.status.providers.integrity import get_integrity_status
from anchorforge.status.providers.overview import get_overview_status
from anchorforge.status.providers.tx import get_tx_status
from anchorforge.status.providers.utxo import get_utxo_status


def _run_status(args: list[str], capsys) -> tuple[int, str, str]:
    exit_code = af_status.main(args)
    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


def _json_status(args: list[str], capsys) -> dict:
    exit_code, stdout, stderr = _run_status(args, capsys)
    assert exit_code == 0, stderr
    assert stderr == ""
    parsed = json.loads(stdout)
    assert set(parsed) == {"data", "meta", "warnings"}
    assert isinstance(parsed["warnings"], list)
    for warning in parsed["warnings"]:
        assert set(warning) == {"context", "level", "message"}
    return parsed


def _context(base_dir: Path) -> StatusContext:
    return StatusContext(
        config_network="test",
        cli_network_override=None,
        effective_network="test",
        config_source=base_dir / "local_config" / ".env",
        base_dir=base_dir,
        output_dir=base_dir / "output",
        database_dir=base_dir / "database",
        wallet_cache_dir=base_dir / "cache" / "wallet",
        public_cache_dir=base_dir / "cache" / "public",
        audit_log_path=base_dir / "output" / "audit_log_test.json",
        header_cache_path=base_dir / "cache" / "public" / "block_headers_test.json",
        default_utxo_store_path=base_dir / "cache" / "wallet" / "utxo_store_test.json",
        default_used_utxo_store_path=base_dir / "cache" / "wallet" / "used_utxo_store_test.json",
        default_tx_store_path=base_dir / "database" / "tx_store_test.json",
        worker_address=None,
        bank_address=None,
        warnings=[],
    )


@pytest.mark.parametrize(
    "args",
    [
        ["--format", "json"],
        ["overview", "--format", "json"],
        ["utxo", "--format", "json"],
        ["tx", "--format", "json"],
        ["integrity", "--format", "json"],
        ["headers", "--format", "json"],
        ["last", "txid", "--format", "json"],
        ["info", "tx", "--txid", "deadbeef", "--format", "json"],
        ["info", "utxo", "--outpoint", "deadbeef:0", "--format", "json"],
    ],
)
def test_status_json_outputs_are_pure_json(args, capsys):
    _json_status(args, capsys)


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["overview"],
        ["utxo"],
        ["tx"],
        ["integrity"],
        ["headers"],
        ["last", "txid"],
        ["last", "tx"],
        ["last", "ir"],
        ["last", "utxo-created"],
        ["last", "utxo-used"],
        ["last", "warnings"],
        ["info", "tx", "--txid", "deadbeef"],
        ["info", "ir", "--keyword", "missing"],
        ["info", "utxo", "--outpoint", "deadbeef:0"],
    ],
)
def test_status_cli_contract_success_paths(args, capsys):
    exit_code, _stdout, _stderr = _run_status(args, capsys)
    assert exit_code == 0


def test_status_invalid_command_is_cli_misuse(capsys):
    exit_code, _stdout, _stderr = _run_status(["not-a-command"], capsys)
    assert exit_code == 2


def test_status_network_override_does_not_mutate_config(capsys):
    before = {
        "ACTIVE_NETWORK_NAME": Config.ACTIVE_NETWORK_NAME,
        "WOC_API_BASE_URL": Config.WOC_API_BASE_URL,
        "ACTIVE_NETWORK_BSV": Config.ACTIVE_NETWORK_BSV,
        "AUDIT_LOG_FILE": Config.AUDIT_LOG_FILE,
        "BLOCK_HEADERS_FILE": Config.BLOCK_HEADERS_FILE,
        "TX_STORE_FILE": Config.TX_STORE_FILE,
    }
    exit_code, _stdout, _stderr = _run_status(["overview", "--network", "main"], capsys)
    assert exit_code == 0
    assert {key: getattr(Config, key) for key in before} == before


def test_status_missing_optional_local_files_are_tolerated(tmp_path):
    context = _context(tmp_path)
    providers = [
        get_overview_status,
        get_utxo_status,
        get_tx_status,
        get_integrity_status,
        get_headers_status,
    ]
    for provider in providers:
        result = provider(context, "normal")
        assert set(result.to_dict()) == {"data", "meta", "warnings"}
        assert result.warnings
    assert not list(tmp_path.rglob("*.json"))


def test_status_json_output_does_not_emit_secret_sentinels(monkeypatch, capsys):
    secret_values = {
        "PRIVATE_KEY_WIF": "SECRET_PRIVATE_SENTINEL",
        "UTXO_STORE_KEY_WIF": "SECRET_UTXO_SENTINEL",
        "PRIVATE_SIGNING_KEY_WIF": "SECRET_SIGNING_SENTINEL",
        "PRIVATE_BANK_KEY_WIF": "SECRET_BANK_SENTINEL",
    }
    for attr, value in secret_values.items():
        monkeypatch.setattr(Config, attr, value)

    parsed = _json_status(["overview", "--format", "json"], capsys)
    serialized = json.dumps(parsed, sort_keys=True)
    for value in secret_values.values():
        assert value not in serialized
