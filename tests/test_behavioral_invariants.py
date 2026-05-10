import hashlib
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from anchorforge import core_defs, wallet_manager
from anchorforge.block_manager import BlockHeaderManager
from anchorforge.config import Config


ROOT = Path(__file__).resolve().parents[1]


def _run_python_with_env(code: str, env_updates: dict[str, str | None]) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    for key, value in env_updates.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _snapshot_tree(path: Path) -> dict[str, tuple[int, str]]:
    snapshot = {}
    for item in sorted(p for p in path.rglob("*") if p.is_file()):
        rel = item.relative_to(path).as_posix()
        data = item.read_bytes()
        snapshot[rel] = (len(data), hashlib.sha256(data).hexdigest())
    return snapshot


def _load_status_module_or_xfail():
    try:
        return importlib.import_module("af_status")
    except ModuleNotFoundError:
        pytest.xfail("af_status is not implemented yet")


def _run_status_or_xfail(args: list[str]) -> int:
    module = _load_status_module_or_xfail()
    if hasattr(module, "main"):
        result = module.main(args)
        return 0 if result is None else int(result)
    if hasattr(module, "main_entry"):
        old_argv = sys.argv[:]
        try:
            sys.argv = ["af_status.py", *args]
            result = module.main_entry()
            return 0 if result is None else int(result)
        finally:
            sys.argv = old_argv
    pytest.xfail("af_status has no callable main/main_entry yet")


def test_af_status_001_strictly_read_only_operation(tmp_path, monkeypatch):
    # AF-STATUS-001
    state = tmp_path / "state"
    _write_json(state / "output" / "audit_log_test.json", [])
    _write_json(state / "database" / "tx_store_test_abcdwxyz.json", {"transactions": []})
    _write_json(state / "cache" / "wallet" / "utxo_store_test_abcdwxyz.json", {"utxos": []})
    before = _snapshot_tree(state)
    monkeypatch.chdir(state)
    _run_status_or_xfail(["overview"])
    assert _snapshot_tree(state) == before


def test_af_status_002_no_implicit_remote_access(monkeypatch):
    # AF-STATUS-002
    def fail_remote(*_args, **_kwargs):
        raise AssertionError("af_status must not call remote APIs without an explicit remote option")

    monkeypatch.setattr("anchorforge.blockchain_api.get_chain_info_woc", fail_remote, raising=False)
    monkeypatch.setattr("anchorforge.blockchain_api.fetch_raw_transaction_hex", fail_remote, raising=False)
    monkeypatch.setattr("anchorforge.blockchain_api.get_block_header", fail_remote, raising=False)
    _run_status_or_xfail(["overview"])


def test_af_status_003_json_stdout_is_valid_json_only(capsys):
    # AF-STATUS-003
    exit_code = _run_status_or_xfail(["overview", "--format", "json"])
    captured = capsys.readouterr()
    assert exit_code == 0
    parsed = json.loads(captured.out)
    assert set(parsed) >= {"meta", "data", "warnings"}


def test_af_status_004_network_override_does_not_mutate_config():
    # AF-STATUS-004
    before = {
        "ACTIVE_NETWORK_NAME": Config.ACTIVE_NETWORK_NAME,
        "WOC_API_BASE_URL": Config.WOC_API_BASE_URL,
        "ACTIVE_NETWORK_BSV": Config.ACTIVE_NETWORK_BSV,
        "AUDIT_LOG_FILE": Config.AUDIT_LOG_FILE,
        "BLOCK_HEADERS_FILE": Config.BLOCK_HEADERS_FILE,
        "TX_STORE_FILE": Config.TX_STORE_FILE,
    }
    _run_status_or_xfail(["overview", "--network", "main"])
    after = {key: getattr(Config, key) for key in before}
    assert after == before


def test_af_status_005_overview_missing_optional_data_warns_not_fails(tmp_path, monkeypatch, capsys):
    # AF-STATUS-005
    monkeypatch.chdir(tmp_path)
    exit_code = _run_status_or_xfail(["overview"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "warning" in (captured.out + captured.err).lower()
    assert not list(tmp_path.rglob("*.json"))


def test_af_status_006_does_not_call_initializing_helpers(monkeypatch):
    # AF-STATUS-006
    forbidden = Mock(side_effect=AssertionError("mutating helper must not be called by af_status"))
    monkeypatch.setattr("anchorforge.wallet_manager._ensure_store_exists", forbidden)
    monkeypatch.setattr("anchorforge.utils.ensure_json_file_exists", forbidden)
    monkeypatch.setattr("anchorforge.wallet_manager.save_utxo_store", forbidden)
    monkeypatch.setattr("anchorforge.wallet_manager.save_used_utxo_store", forbidden)
    monkeypatch.setattr("anchorforge.wallet_manager.save_tx_store", forbidden)
    monkeypatch.setattr("anchorforge.core_defs.save_audit_log", forbidden)
    monkeypatch.setattr("anchorforge.block_manager.BlockHeaderManager.save", forbidden)
    monkeypatch.setattr("anchorforge.blockchain_service.sync_block_headers", forbidden)
    _run_status_or_xfail(["overview"])


def test_config_001_config_import_is_canonical():
    # CONFIG-001
    assert Config.BASE_DIR == ROOT
    assert Config.LOCAL_CONFIG_DIR == ROOT / "local_config"
    assert Config.ENV_PATH == ROOT / "local_config" / ".env"
    assert Config.OUTPUT_DIR.exists()
    assert Config.DATABASE_DIR.exists()
    assert Config.WALLET_CACHE_DIR.exists()
    assert Config.PUBLIC_CACHE_DIR.exists()
    assert Config.RUNTIME_DIR.exists()


def test_config_002_env_path_is_fixed():
    # CONFIG-002
    code = (
        "from anchorforge.config import Config; "
        "import json; "
        "print(json.dumps({'env_path': str(Config.ENV_PATH), 'base': str(Config.BASE_DIR)}))"
    )
    result = _run_python_with_env(code, {})
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout.strip().splitlines()[-1])
    assert data["env_path"].endswith("local_config/.env")
    assert data["base"] == str(ROOT)


def test_config_003_network_defaults_to_test_when_unset():
    # CONFIG-003
    code = (
        "from anchorforge.config import Config; "
        "import json; "
        "print(json.dumps({'network': Config.ACTIVE_NETWORK_NAME, "
        "'prefix': Config.NETWORK_PREFIX, 'url': Config.WOC_API_BASE_URL}))"
    )
    result = _run_python_with_env(code, {"NETWORK": None})
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout.strip().splitlines()[-1])
    assert data == {
        "network": "test",
        "prefix": "TESTNET_",
        "url": "https://api.whatsonchain.com/v1/bsv/test",
    }


def test_config_004_invalid_network_fails_at_config_load():
    # CONFIG-004
    result = _run_python_with_env("from anchorforge.config import Config", {"NETWORK": "invalid"})
    assert result.returncode != 0
    assert "Invalid NETWORK" in result.stderr


def test_config_005_network_specific_secrets_are_prefix_selected():
    # CONFIG-005
    code = (
        "from anchorforge.config import Config; "
        "import json; "
        "print(json.dumps({'private': Config.PRIVATE_KEY_WIF, "
        "'utxo': Config.UTXO_STORE_KEY_WIF, 'bank': Config.BANK_ADDRESS}))"
    )
    base_env = {
        "TESTNET_PRIVATE_KEY_WIF": "test-private",
        "TESTNET_UTXO_STORE_KEY_WIF": "test-utxo",
        "TESTNET_BANK_ADDRESS": "test-bank",
        "MAINNET_PRIVATE_KEY_WIF": "main-private",
        "MAINNET_UTXO_STORE_KEY_WIF": "main-utxo",
        "MAINNET_BANK_ADDRESS": "main-bank",
    }
    test_result = _run_python_with_env(code, {**base_env, "NETWORK": "test"})
    main_result = _run_python_with_env(code, {**base_env, "NETWORK": "main"})
    assert json.loads(test_result.stdout.strip().splitlines()[-1]) == {
        "private": "test-private",
        "utxo": "test-utxo",
        "bank": "test-bank",
    }
    assert json.loads(main_result.stdout.strip().splitlines()[-1]) == {
        "private": "main-private",
        "utxo": "main-utxo",
        "bank": "main-bank",
    }


def test_config_006_wallet_validation_is_explicit(monkeypatch):
    # CONFIG-006
    monkeypatch.setattr(Config, "PRIVATE_KEY_WIF", None)
    monkeypatch.setattr(Config, "UTXO_STORE_KEY_WIF", None)
    with pytest.raises(ValueError, match="Missing wallet keys"):
        Config.validate_wallet_config()


@pytest.mark.parametrize(
    ("network", "expected"),
    [
        ("test", ("utxo_store_test.json", "used_utxo_store_test.json", "block_headers_test.json", "tx_store_test.json", "application_test.log", "audit_log_test.json")),
        ("main", ("utxo_store_main.json", "used_utxo_store_main.json", "block_headers_main.json", "tx_store_main.json", "application_main.log", "audit_log_main.json")),
    ],
)
def test_path_001_static_config_paths_keep_existing_names(network, expected):
    # PATH-001
    code = (
        "from anchorforge.config import Config; "
        "import json; "
        "print(json.dumps([Config.UTXO_STORE_FILE, Config.USED_UTXO_STORE_FILE, "
        "Config.BLOCK_HEADERS_FILE, Config.TX_STORE_FILE, Config.LOG_FILE, Config.AUDIT_LOG_FILE]))"
    )
    result = _run_python_with_env(code, {"NETWORK": network})
    assert result.returncode == 0, result.stderr
    paths = json.loads(result.stdout.strip().splitlines()[-1])
    assert tuple(Path(path).name for path in paths) == expected


def test_path_002_address_derived_store_paths_are_authoritative(monkeypatch, tmp_path):
    # PATH-002
    monkeypatch.setattr(Config, "WALLET_CACHE_DIR", tmp_path / "wallet")
    monkeypatch.setattr(Config, "CACHE_DIR", tmp_path / "wallet")
    monkeypatch.setattr(Config, "DATABASE_DIR", tmp_path / "database")
    address = "abcd1234567890wxyz"
    assert wallet_manager._get_filename_for_address(address, "test", "utxo") == str(
        tmp_path / "wallet" / "utxo_store_test_abcdwxyz.json"
    )
    assert wallet_manager._get_filename_for_address(address, "test", "used") == str(
        tmp_path / "wallet" / "used_utxo_store_test_abcdwxyz.json"
    )
    assert wallet_manager._get_filename_for_address(address, "test", "tx") == str(
        tmp_path / "database" / "tx_store_test_abcdwxyz.json"
    )


def test_path_003_simulation_mode_changes_store_suffix(monkeypatch, tmp_path):
    # PATH-003
    monkeypatch.setattr(Config, "WALLET_CACHE_DIR", tmp_path)
    normal = wallet_manager._get_filename_for_address("abcd1234wxyz", "test", "utxo")
    sim = wallet_manager._get_filename_for_address("abcd1234wxyz", "test", "utxo", simulation=True)
    assert normal.endswith(".json")
    assert sim.endswith(".sim.json")
    assert sim.removesuffix(".sim.json") == normal.removesuffix(".json")


def test_path_004_unknown_store_types_fall_back_to_wallet_cache(monkeypatch, tmp_path, caplog):
    # PATH-004
    monkeypatch.setattr(Config, "WALLET_CACHE_DIR", tmp_path)
    path = wallet_manager._get_filename_for_address("abcd1234wxyz", "test", "foo")
    assert path == str(tmp_path / "foo_store_test_abcdwxyz.json")
    assert "Unknown file_type" in caplog.text


@pytest.mark.parametrize(
    ("store_type", "expected"),
    [
        ("utxo", {"address": "", "network": "", "utxos": []}),
        ("used", {"address": "", "network": "", "used_utxos": []}),
        ("tx", {"address": "", "network": "", "transactions": []}),
    ],
)
def test_store_001_store_initialization_schemas_are_stable(tmp_path, store_type, expected):
    # STORE-001
    path = tmp_path / f"{store_type}.json"
    wallet_manager._ensure_store_exists(str(path), store_type)
    assert json.loads(path.read_text(encoding="utf-8")) == expected
    path.write_text('{"custom": true}', encoding="utf-8")
    wallet_manager._ensure_store_exists(str(path), store_type)
    assert json.loads(path.read_text(encoding="utf-8")) == {"custom": True}


def test_store_002_store_loaders_fail_soft(tmp_path):
    # STORE-002
    bad = tmp_path / "bad.json"
    bad.write_text("{bad json", encoding="utf-8")
    with bad.open("r", encoding="utf-8") as f:
        assert wallet_manager.load_utxo_store(f) == {"address": "", "utxos": [], "network": ""}
    with bad.open("r", encoding="utf-8") as f:
        assert wallet_manager.load_used_utxo_store(f) == {"address": "", "used_utxos": [], "network": ""}
    with bad.open("r", encoding="utf-8") as f:
        assert wallet_manager.load_tx_store(f) == {"address": "", "transactions": [], "network": ""}
    with bad.open("r", encoding="utf-8") as f:
        assert core_defs.load_audit_log(f) == []
    assert BlockHeaderManager(str(bad)).headers == {}


def test_store_003_store_saves_truncate_and_pretty_print(tmp_path):
    # STORE-003
    path = tmp_path / "store.json"
    path.write_text('{"old": true, "padding": "xxxxxxxxxxxxxxxxxxxxxxxx"}', encoding="utf-8")
    with path.open("r+", encoding="utf-8") as f:
        wallet_manager.save_tx_store(f, {"transactions": []})
    assert json.loads(path.read_text(encoding="utf-8")) == {"transactions": []}
    assert "padding" not in path.read_text(encoding="utf-8")
    assert "\n    " in path.read_text(encoding="utf-8")


def test_utxo_001_audit_event_locks_mutable_stores_together():
    # UTXO-001
    source = (ROOT / "anchorforge" / "manager.py").read_text(encoding="utf-8")
    assert 'portalocker.Lock(path_audit, "r+"' in source
    assert 'portalocker.Lock(path_tx,    "r+"' in source
    assert 'portalocker.Lock(path_used,  "r+"' in source
    assert 'portalocker.Lock(path_utxo,  "r+"' in source


def test_utxo_002_dry_run_does_not_save_audit_or_store_changes():
    # UTXO-002
    source = (ROOT / "anchorforge" / "manager.py").read_text(encoding="utf-8")
    assert 'if dry_run:\n                    logger.info("Dry run complete. No changes saved.")\n                    return True' in source


def test_utxo_003_no_broadcast_uses_simulation_files():
    # UTXO-003
    source = (ROOT / "anchorforge" / "manager.py").read_text(encoding="utf-8")
    assert "simulation=no_broadcast" in source
    assert 'path_audit = path_audit.replace(".json", ".sim.json")' in source


def test_utxo_004_successful_audit_updates_wallet_stores():
    # UTXO-004
    source = (ROOT / "anchorforge" / "manager.py").read_text(encoding="utf-8")
    assert 'record["blockchain_record"].update' in source
    assert '"status": "broadcasted"' in source
    assert 'store_utxo["utxos"] = [u for u in store_utxo["utxos"]' in source
    assert 'store_used["used_utxos"].append(u)' in source
    assert 'store_utxo["utxos"].extend(new_utxos)' in source


def test_tx_001_created_transactions_are_appended_to_tx_store():
    # TX-001
    source = (ROOT / "anchorforge" / "publisher.py").read_text(encoding="utf-8")
    assert 'tx_store["transactions"].append' in source
    assert '"txid": tx.txid()' in source
    assert '"rawtx": tx.hex()' in source
    assert '"timestamp": datetime.now(timezone.utc).isoformat()' in source


def test_tx_002_missing_source_raw_transactions_are_cached():
    # TX-002
    source = (ROOT / "anchorforge" / "publisher.py").read_text(encoding="utf-8")
    assert "fetch_raw_transaction_hex(utxo['txid'])" in source
    assert 'if not any(tx[\'txid\'] == utxo[\'txid\'] for tx in tx_store["transactions"]):' in source
    assert '"rawtx": raw_source_tx_hex' in source


def test_audit_001_audit_log_format_is_a_list(tmp_path):
    # AUDIT-001
    bad = tmp_path / "audit.json"
    bad.write_text("{bad json", encoding="utf-8")
    with bad.open("r", encoding="utf-8") as f:
        assert core_defs.load_audit_log(f) == []
    good = tmp_path / "audit_good.json"
    with good.open("w+", encoding="utf-8") as f:
        core_defs.save_audit_log(f, [{"log_id": "one"}])
    assert json.loads(good.read_text(encoding="utf-8")) == [{"log_id": "one"}]


def test_audit_002_monitor_confirms_records_in_place():
    # AUDIT-002
    source = (ROOT / "anchorforge" / "manager.py").read_text(encoding="utf-8")
    assert 'current_bc_rec["status"] = "confirmed"' in source
    assert 'current_bc_rec["block_hash"] = tx_info["blockhash"]' in source
    assert 'current_bc_rec["block_height"] = tx_info["blockheight"]' in source
    assert "Config.TSC_PROOF_FIELD" in source
    assert 'utxo["height"] = tx_info["blockheight"]' in source


def test_headers_001_header_cache_missing_or_corrupt_loads_empty(tmp_path):
    # HEADERS-001
    missing = tmp_path / "missing.json"
    manager = BlockHeaderManager(str(missing))
    assert manager.headers == {}
    assert not missing.exists()
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{bad json", encoding="utf-8")
    assert BlockHeaderManager(str(corrupt)).headers == {}


def test_headers_002_header_cache_save_creates_parent_directory(tmp_path):
    # HEADERS-002
    path = tmp_path / "nested" / "headers.json"
    manager = BlockHeaderManager(str(path))
    manager.headers["abc"] = {"hash": "abc", "height": 1}
    manager.save()
    assert json.loads(path.read_text(encoding="utf-8")) == {"abc": {"hash": "abc", "height": 1}}


def test_headers_003_sync_cli_defaults_to_config_header_path():
    # HEADERS-003
    source = (ROOT / "af_sync.py").read_text(encoding="utf-8")
    assert "Config.BLOCK_HEADERS_FILE" in source
    assert "output_file = Config.BLOCK_HEADERS_FILE" in source
    assert "BlockHeaderManager(output_file)" in source


def test_headers_004_sync_network_override_is_ad_hoc():
    # HEADERS-004
    source = (ROOT / "af_sync.py").read_text(encoding="utf-8")
    assert "Config.ACTIVE_NETWORK_NAME = args.network" in source
    assert "Config.WOC_API_BASE_URL" in source
    assert "Config.BLOCK_HEADERS_FILE" in source


def test_verify_001_verify_network_override_is_temporary():
    # VERIFY-001
    source = (ROOT / "af_verify.py").read_text(encoding="utf-8")
    assert "original_network_config = Config.ACTIVE_NETWORK_NAME" in source
    assert "Config.ACTIVE_NETWORK_NAME = args.network" in source
    assert "finally:" in source
    assert "Config.ACTIVE_NETWORK_NAME = original_network_config" in source


def test_verify_002_verifier_header_lookup_uses_config_header_file():
    # VERIFY-002
    source = (ROOT / "anchorforge" / "verifier.py").read_text(encoding="utf-8")
    assert "Config.BLOCK_HEADERS_FILE" in source
    assert "header_manager = BlockHeaderManager(header_file)" in source


def test_cli_001_existing_cli_entry_points_remain_compatible():
    # CLI-001
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'af-anchor = "af_anchor:main_entry"' in pyproject
    assert 'af-verify = "af_verify:main_entry"' in pyproject
    assert 'af-sync = "af_sync:main_entry"' in pyproject
    assert 'af-monitor = "af_monitor:main_entry"' in pyproject


def test_secrets_001_status_must_not_expose_secret_material(monkeypatch, capsys):
    # SECRETS-001
    monkeypatch.setattr(Config, "PRIVATE_KEY_WIF", "SECRET_PRIVATE_SENTINEL")
    monkeypatch.setattr(Config, "UTXO_STORE_KEY_WIF", "SECRET_UTXO_SENTINEL")
    monkeypatch.setattr(Config, "PRIVATE_SIGNING_KEY_WIF", "SECRET_SIGNING_SENTINEL")
    monkeypatch.setattr(Config, "PRIVATE_BANK_KEY_WIF", "SECRET_BANK_SENTINEL")
    _run_status_or_xfail(["overview"])
    output = capsys.readouterr().out
    assert "SECRET_" not in output

