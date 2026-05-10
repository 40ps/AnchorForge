# AnchorForge Behavioral Invariants

This document defines behavioral invariants that must be preserved when adding
new inspection and status tooling.

The immediate use case is `af_status.py`, but the invariants also document
current AnchorForge behavior around configuration, local stores, audit logs, and
header cache handling.


`af_status.py` must not change existing behavior of:

* configuration loading
* network selection
* path resolution
* UTXO store handling
* transaction storage
* audit log handling
* header cache handling
* existing CLI tools
* secret handling
---

## Invariant ID Scheme

Invariant IDs use domain prefixes:

- `AF-STATUS-*` – status tool specific invariants
- `CONFIG-*` – configuration behavior
- `PATH-*` – path resolution behavior
- `STORE-*` – generic store behavior
- `UTXO-*` – UTXO store behavior
- `TX-*` – transaction store behavior
- `AUDIT-*` – audit log behavior
- `HEADERS-*` – header cache behavior
- `CLI-*` – existing CLI behavior
- `SECRETS-*` – secret handling and output safety
---

## Status-Specific Invariants

### AF-STATUS-001: Strictly Read-Only Operation

**Sources**

* Planned: `af_status.py`
* Planned: `anchorforge/status/*`

**Expected behavior**

`af_status` must never create, modify, truncate, normalize, repair, or initialize
files. This includes config files, wallet stores, transaction stores, audit
logs, header caches, application logs, runtime files, and directories.

**Characterization test**

Create representative local state, snapshot file paths, sizes, hashes, and
mtimes, run all status commands, and assert the tree is unchanged byte-for-byte.

**Status dependency**

Yes.

### AF-STATUS-002: No Implicit Remote Access

**Sources**

* Planned: status providers and resolvers
* Existing remote modules must not be called implicitly:
  * `anchorforge/blockchain_api.py`
  * `anchorforge/blockchain_service.py`

**Expected behavior**

`af_status` must inspect local data only unless a future explicit remote or
compare option is used.

**Characterization test**

Patch all blockchain API and HTTP functions to raise if called. Run default
overview and all local subcommands. Assert no remote functions are called.

**Status dependency**

Yes.

### AF-STATUS-003: JSON Output Is JSON Only

**Sources**

* Planned: JSON formatter
* Planned: CLI output handling

**Expected behavior**

When `--format json` is used, stdout must contain valid JSON only. No banners,
logging, progress text, hints, or human warning lines may be mixed into stdout.
Warnings must be represented inside the JSON object.

**Characterization test**

Run representative status commands with `--format json`, parse the complete
stdout with `json.loads`, and assert stable top-level keys:

```json
{
  "meta": {},
  "data": {},
  "warnings": []
}
```

**Status dependency**

Yes.

### AF-STATUS-004: Network Override Must Not Mutate Global Config

**Sources**

* Existing: `anchorforge/config.py`
* Planned: status context and network resolver

**Expected behavior**

`af_status --network main|test` may compute an effective network for the status
context, but it must not permanently mutate `Config.ACTIVE_NETWORK_NAME`,
`Config.WOC_API_BASE_URL`, `Config.ACTIVE_NETWORK_BSV`, or precomputed
`Config.*_FILE` values.

**Characterization test**

Record relevant `Config` attributes in-process, invoke status with each network
override, and assert all original attributes are unchanged after normal return
and after an induced exception.

**Status dependency**

Yes.

### AF-STATUS-005: Overview Fails Soft on Missing Local Data

**Sources**

* Planned: overview provider
* Existing local data sources:
  * UTXO store
  * used UTXO store
  * TX store
  * audit log
  * header cache

**Expected behavior**

Missing optional local state files must produce warnings and partial output, not
a hard failure. Configuration failures remain separate.

**Characterization test**

Run overview with each optional file missing, then with multiple optional files
missing. Assert exit code `0`, visible warnings, partial data, and no file
creation.

**Status dependency**

Yes.

### AF-STATUS-006: Do Not Reuse Initializing Helpers

**Sources**

Status code must not call mutating helpers such as:

* `wallet_manager._ensure_store_exists`
* `utils.ensure_json_file_exists`
* `wallet_manager.save_utxo_store`
* `wallet_manager.save_used_utxo_store`
* `wallet_manager.save_tx_store`
* `core_defs.save_audit_log`
* `BlockHeaderManager.save`
* `blockchain_service.sync_block_headers`

**Expected behavior**

Status providers may reuse pure readers only when they do not create, repair,
fetch, or persist state. Missing stores must be reported, not initialized.

**Characterization test**

Patch forbidden helpers to raise if invoked. Run all status commands. Assert
status succeeds where local files exist and fails softly with warnings where
optional local files are missing.

**Status dependency**

Yes.

---

## Existing Behavior Invariants

### CONFIG-001: Config Import Is Canonical

**Sources**

* `anchorforge/config.py`

**Expected behavior**

Importing `Config` resolves `BASE_DIR`, loads `local_config/.env` if present,
creates configured runtime directories, resolves network values, and exposes
configuration through class attributes.

**Characterization test**

Import `Config` in an isolated process with controlled environment values and
assert paths, network values, and directory creation match current behavior.

**Status dependency**

Yes.

### CONFIG-002: `.env` Path Is Fixed

**Sources**

* `Config.LOCAL_CONFIG_DIR`
* `Config.ENV_PATH`

**Expected behavior**

The only repository-local `.env` path loaded by default is
`BASE_DIR/local_config/.env`. Missing `.env` is tolerated.

**Characterization test**

Run config import with and without `local_config/.env`; assert no crash without
the file and correct value loading when present.

**Status dependency**

Yes.

### CONFIG-003: Network Defaults to Test

**Sources**

* `Config.ACTIVE_NETWORK_NAME`
* `Config.NETWORK_PREFIX`
* `Config.ACTIVE_NETWORK_BSV`

**Expected behavior**

If `NETWORK` is unset, active network is `test`, prefix is `TESTNET_`, and the
default WOC URL points to testnet.

**Characterization test**

Clear `NETWORK`, import config in a subprocess, and assert active network,
network prefix, BSV network, and WOC URL.

**Status dependency**

Yes.

### CONFIG-004: Invalid Network Fails at Config Load

**Sources**

* `anchorforge/config.py`

**Expected behavior**

Any network value other than `test` or `main` raises `ValueError` during config
initialization.

**Characterization test**

Run config import with `NETWORK=invalid` and assert non-zero failure with a
message naming the valid values.

**Status dependency**

Yes.

### CONFIG-005: Network-Specific Secrets Are Prefix Selected

**Sources**

* `Config.NETWORK_PREFIX`
* `Config.PRIVATE_KEY_WIF`
* `Config.UTXO_STORE_KEY_WIF`
* `Config.PRIVATE_SIGNING_KEY_WIF`
* `Config.PRIVATE_BANK_KEY_WIF`
* `Config.BANK_ADDRESS`

**Expected behavior**

The active network selects `TESTNET_*` or `MAINNET_*` values. Values for the
inactive network are not exposed through the active secret attributes.

**Characterization test**

Set distinct testnet and mainnet sentinel values, import under each network, and
assert only matching prefix values are active.

**Status dependency**

Yes.

### CONFIG-006: Wallet Validation Is Explicit

**Sources**

* `Config.validate_wallet_config`
* `af_anchor.py`

**Expected behavior**

Wallet key validation is explicit and requires `PRIVATE_KEY_WIF` and
`UTXO_STORE_KEY_WIF`. Read-only tools must not call this validation just to
inspect local state.

**Characterization test**

Import config with missing wallet keys and assert no import failure. Separately
call `validate_wallet_config()` and assert it raises.

**Status dependency**

Indirect.

### PATH-001: Static Config Paths Keep Existing Names

**Sources**

* `Config.UTXO_STORE_FILE`
* `Config.USED_UTXO_STORE_FILE`
* `Config.BLOCK_HEADERS_FILE`
* `Config.TX_STORE_FILE`
* `Config.LOG_FILE`
* `Config.AUDIT_LOG_FILE`

**Expected behavior**

Config exposes network-derived default filenames such as
`audit_log_test.json`, `tx_store_main.json`, and `block_headers_test.json`.

**Characterization test**

Import config with `NETWORK=test` and `NETWORK=main` and assert exact suffixes.

**Status dependency**

Yes.

### PATH-002: Address-Derived Store Paths Are Authoritative for Wallet State

**Sources**

* `wallet_manager._get_filename_for_address`
* `manager.log_audit_event`
* `manager.perform_backup`
* `main_wallet_setup`

**Expected behavior**

Active wallet UTXO, used UTXO, and TX stores are derived from address and
network, using the short address form `address[:4] + address[-4:]`.

**Characterization test**

Call `_get_filename_for_address` for `utxo`, `used`, and `tx` with a known
address and network. Assert exact prefixes, directories, and short-address
suffixes.

**Status dependency**

Yes.

### PATH-003: Simulation Mode Changes Store Suffix

**Sources**

* `wallet_manager._get_filename_for_address`
* `manager.log_audit_event`

**Expected behavior**

With `simulation=True`, derived store paths end in `.sim.json`. Other path
components remain file-type dependent.

**Characterization test**

Call `_get_filename_for_address` with simulation on and off and assert only the
suffix changes.

**Status dependency**

Yes, if simulation files are reported.

### PATH-004: Unknown Store Types Fall Back to Wallet Cache

**Sources**

* `wallet_manager._get_filename_for_address`

**Expected behavior**

Unknown file types produce `<file_type>_store_<network>_<short>.json` under the
wallet cache directory and log a warning.

**Characterization test**

Call `_get_filename_for_address(..., file_type="foo")` and assert the fallback
path and warning.

**Status dependency**

No.

### STORE-001: Store Initialization Schemas Are Stable

**Sources**

* `wallet_manager._ensure_store_exists`

**Expected behavior**

Missing stores are initialized with:

* UTXO: `{"address": "", "network": "", "utxos": []}`
* used UTXO: `{"address": "", "network": "", "used_utxos": []}`
* TX: `{"address": "", "network": "", "transactions": []}`

Existing files are left untouched.

**Characterization test**

Create temp paths, call `_ensure_store_exists` for each store type, and assert
schemas. Modify an existing file, call again, and assert content is unchanged.

**Status dependency**

Yes for schema interpretation, but status must not call this helper.

### STORE-002: Store Loaders Fail Soft

**Sources**

* `wallet_manager.load_utxo_store`
* `wallet_manager.load_used_utxo_store`
* `wallet_manager.load_tx_store`
* `core_defs.load_audit_log`
* `BlockHeaderManager.load`

**Expected behavior**

Malformed or missing data returns empty defaults rather than raising.

**Characterization test**

Open invalid JSON files and assert default structures are returned.

**Status dependency**

Yes.

### STORE-003: Store Saves Truncate and Pretty Print

**Sources**

* `wallet_manager.save_utxo_store`
* `wallet_manager.save_used_utxo_store`
* `wallet_manager.save_tx_store`
* `core_defs.save_audit_log`

**Expected behavior**

Save helpers seek to the beginning, dump JSON with `indent=4`, and truncate old
content.

**Characterization test**

Write long JSON, save a shorter object through each helper, and assert no
trailing bytes remain.

**Status dependency**

No. Status must not call save helpers.

### UTXO-001: Audit Event Locks Mutable Stores Together

**Sources**

* `manager.log_audit_event`

**Expected behavior**

Audit, TX, used UTXO, and UTXO stores are locked together before transaction
creation and state mutation.

**Characterization test**

Mock `portalocker.Lock` and assert lock targets and order.

**Status dependency**

No direct dependency.

### UTXO-002: Dry Run Does Not Save Audit or Store Changes

**Sources**

* `manager.log_audit_event`

**Expected behavior**

If transaction creation succeeds in dry-run mode, the function returns before
appending audit records or saving stores.

**Characterization test**

Mock `publisher.create_op_return_transaction` to return a dry-run tuple and
assert no save helper is called and files are unchanged.

**Status dependency**

No.

### UTXO-003: No-Broadcast Uses Simulation Files

**Sources**

* `manager.log_audit_event`
* `publisher.create_op_return_transaction`

**Expected behavior**

`no_broadcast=True` uses `.sim.json` UTXO, used UTXO, TX, and audit files while
still updating those simulation stores.

**Characterization test**

Mock successful no-broadcast transaction creation and assert real files remain
untouched while `.sim.json` paths are used.

**Status dependency**

Yes, if simulation files are inspected.

### UTXO-004: Successful Audit Updates Wallet Stores

**Sources**

* `manager.log_audit_event`

**Expected behavior**

Consumed UTXOs are removed from active UTXOs, marked used and appended to the
used store, new outputs are appended to active UTXOs, TX store is saved, and an
audit record is appended with `status` set to `broadcasted`.

**Characterization test**

Mock transaction success with known consumed and new UTXOs. Assert resulting
store and audit JSON content.

**Status dependency**

Yes.

### TX-001: Created Transactions Are Appended to TX Store

**Sources**

* `publisher.create_op_return_transaction`

**Expected behavior**

New OP_RETURN transactions are appended to `tx_store["transactions"]` as
objects containing `txid`, `rawtx`, and `timestamp`.

**Characterization test**

Mock transaction creation and broadcast, then assert the TX store gains the raw
transaction entry.

**Status dependency**

Yes.

### TX-002: Missing Source Raw Transactions Are Cached

**Sources**

* `publisher._fetch_inputs_for_amount`
* `af_utxo_manager._update_tx_store_with_raw_txs`

**Expected behavior**

If a selected UTXO's source transaction is missing from the TX store, existing
creation and repair flows may fetch and cache the raw source transaction.

**Characterization test**

Mock a UTXO store, empty TX store, and remote raw transaction fetch. Assert a
source transaction entry is appended.

**Status dependency**

Yes for interpreting TX store completeness. Status must not perform fetching.

### AUDIT-001: Audit Log Format Is a List

**Sources**

* `core_defs.load_audit_log`
* `core_defs.save_audit_log`
* `manager.log_audit_event`

**Expected behavior**

The audit log is a JSON list of records. Missing or invalid audit data loads as
`[]`. New records are appended to the list.

**Characterization test**

Load missing and invalid audit logs and assert `[]`. Mock append flow and assert
list length increases.

**Status dependency**

Yes.

### AUDIT-002: Monitor Confirms Records In Place

**Sources**

* `manager.monitor_pending_transactions`

**Expected behavior**

Pending or broadcasted audit records are updated in place with `confirmed`
status, block hash, block height, confirmation timestamp, TSC proof fields, and
matching UTXO height updates.

**Characterization test**

Mock transaction status and proof APIs over temp audit and UTXO files. Run a
controlled monitor iteration and assert updated fields.

**Status dependency**

Yes.

### HEADERS-001: Header Cache Missing or Corrupt Loads Empty

**Sources**

* `BlockHeaderManager.load`

**Expected behavior**

Missing or invalid header cache loads as `{}` and does not create a file until
`save()` is called.

**Characterization test**

Instantiate `BlockHeaderManager` with missing and corrupt paths. Assert
`headers == {}` and no missing file is created.

**Status dependency**

Yes.

### HEADERS-002: Header Cache Save Creates Parent Directory

**Sources**

* `BlockHeaderManager.save`

**Expected behavior**

`save()` creates the parent directory when needed and writes `headers` as JSON.

**Characterization test**

Instantiate a manager on a nested temp path, set headers, save, and assert file
content.

**Status dependency**

No. Status must not save.

### HEADERS-003: Sync CLI Defaults to Config Header Path

**Sources**

* `af_sync.py`

**Expected behavior**

Without `--output`, `af_sync` uses `Config.BLOCK_HEADERS_FILE` if available,
otherwise a local fallback filename.

**Characterization test**

Mock command-line args and `BlockHeaderManager`; assert the configured header
path is passed.

**Status dependency**

No direct dependency.

### HEADERS-004: Sync Network Override Is Ad Hoc

**Sources**

* `af_sync.py`

**Expected behavior**

`af_sync --network` mutates `Config.ACTIVE_NETWORK_NAME` and
`Config.WOC_API_BASE_URL`, but it does not recompute every precomputed config
path.

**Characterization test**

Run `af_sync` with mocked network calls and assert the current mutation behavior.

**Status dependency**

No. Status must not copy this mutation behavior.

### VERIFY-001: Verify Network Override Is Temporary

**Sources**

* `af_verify.py`

**Expected behavior**

`af_verify --network` temporarily mutates `Config.ACTIVE_NETWORK_NAME` during the
run and restores it in `finally`.

**Characterization test**

Mock verifier runner and invoke `af_verify` with a network override. Assert the
original active network is restored after success and failure.

**Status dependency**

No.

### VERIFY-002: Verifier Header Lookup Uses Config Header File

**Sources**

* `verifier.audit_records_runner`

**Expected behavior**

The verifier initializes `BlockHeaderManager` from `Config.BLOCK_HEADERS_FILE`
if available.

**Characterization test**

Patch `Config.BLOCK_HEADERS_FILE` and `BlockHeaderManager`, call the runner, and
assert the configured path is used.

**Status dependency**

Yes for header readiness semantics.

### CLI-001: Existing CLI Entry Points Remain Compatible

**Sources**

* `pyproject.toml`
* `af_anchor.py`
* `af_verify.py`
* `af_sync.py`
* `af_monitor.py`

**Expected behavior**

Existing console commands and script entry points keep their current names,
argument behavior, output behavior, and side effects.

**Characterization test**

Run smoke tests for existing CLI help or safe minimal invocations. Assert exit
codes and output shape remain stable.

**Status dependency**

No direct dependency.

### SECRETS-001: Status Must Not Expose Secret Material

**Sources**

* `anchorforge/config.py`
* `local_config/.env`
* planned status formatters

**Expected behavior**

Existing config exposes secret values as attributes, but status output must never
include WIFs, seed phrases, private keys, private PEMs, or API keys. Only safe
derived or public information may be shown, such as addresses or presence flags.

**Characterization test**

Set sentinel secret values in environment or `.env`, run status in text and JSON
formats, and assert sentinels never appear in stdout, stderr, or parsed JSON.

**Status dependency**

Yes.

---

## Characterization Test Plan

### 1. Existing Behavior Guard Tests

Before implementing `af_status`, add characterization tests for the current
configuration, network, path, UTXO, TX, audit, header, and CLI behavior. These
tests protect the existing codebase from accidental changes introduced by status
tooling.

### 2. Read-Only Status Harness

Create a fixture with representative local state files. Snapshot file inventory,
hashes, sizes, and mtimes. Run every status command and assert the state tree is
unchanged.

### 3. Missing-Data Overview Matrix

Run overview with:

* no UTXO store
* no used UTXO store
* no TX store
* no audit log
* no header cache
* multiple missing files

Assert exit code `0`, useful warnings, partial data, and no file creation.

### 4. No-Remote Local Mode Tests

Patch all remote API and HTTP functions to fail if called. Run default overview
and all local subcommands. Assert no remote calls occur.

### 5. JSON Contract Tests

Run representative commands with `--format json`. Parse complete stdout as JSON
and assert the stable top-level structure:

* `meta`
* `data`
* `warnings`

Assert no human text is mixed into stdout.

### 6. Network Override Isolation Tests

Invoke status in-process with `--network main` and `--network test`. Assert
global `Config` attributes are unchanged after the call. Assert output reports
both config network and effective network.

### 7. Forbidden Helper Tests

Patch state-mutating helpers to raise if invoked, including:

* `wallet_manager._ensure_store_exists`
* `utils.ensure_json_file_exists`
* `wallet_manager.save_utxo_store`
* `wallet_manager.save_used_utxo_store`
* `wallet_manager.save_tx_store`
* `core_defs.save_audit_log`
* `BlockHeaderManager.save`
* `blockchain_service.sync_block_headers`
* blockchain API fetch/broadcast functions

Run all status commands and assert clean completion with existing local data and
soft warnings with missing optional data.

### 8. Secret Redaction Tests

Use sentinel values for WIFs, API keys, and private material. Run text and JSON
status output. Assert sentinel values do not appear anywhere in output.

