# AnchorForge Status Tool Architecture

This document proposes the implementation architecture for `af_status.py`.

It complements:

* `docs/specs/af_status_spec.md`
* `docs/standards/behavioral_invariants.md`
* `prompts/codegen/af_status_codegen.md`

The design goal is a read-only local inspection tool that does not change
existing AnchorForge behavior.

---

## Design Constraints

`af_status.py` must:

* respect all behavioral invariants in `docs/standards/behavioral_invariants.md`
* keep existing CLI tools and library behavior unchanged
* remain strictly read-only
* not introduce additional writes beyond current `Config` import-time behavior
* avoid remote API calls unless a future explicit remote/compare option is added
* avoid helper functions that create, initialize, repair, normalize, truncate, or
  save local state
* never expose secret values
* support deterministic text and JSON output

Current behavior note:

Importing `anchorforge.config.Config` may create configured runtime directories.
This is existing behavior and is documented by the behavioral invariants.
`af_status` must not introduce any additional writes beyond that current
import-time behavior. Future refactoring should isolate configuration loading
from directory creation so read-only tools can inspect configuration without
filesystem side effects.

---

## Proposed File Structure

```text
af_status.py

anchorforge/
  status/
    __init__.py
    context.py
    resolvers.py
    readers.py
    providers/
      __init__.py
      overview.py
      utxo.py
      tx.py
      integrity.py
      headers.py
      warnings.py
      info.py
      last.py
    formatters/
      __init__.py
      text.py
      json.py
```

### `af_status.py`

Thin CLI frontend:

* argument parsing
* command dispatch
* output routing
* exit-code mapping

No business logic should live in the CLI script.

### `anchorforge/status/context.py`

Defines immutable status context objects:

* config snapshot
* config network
* CLI network override
* effective network
* config source path
* resolved local paths
* detected public addresses
* accumulated warnings

The context must not mutate `Config`.

### `anchorforge/status/resolvers.py`

Read-only resolution helpers:

* network resolution
* path resolution
* wallet address derivation when safe
* address-derived store path resolution
* legacy/current local file discovery by glob pattern

Resolvers may compute paths but must not create files or directories.

### `anchorforge/status/readers.py`

Status-local file readers:

* read JSON files in read-only mode
* tolerate missing files
* tolerate malformed JSON
* validate expected top-level type
* return data plus structured warnings

Readers must not call existing helpers that initialize or repair state.

### `anchorforge/status/providers/*`

Domain-specific providers:

* `overview.py`
* `utxo.py`
* `tx.py`
* `integrity.py`
* `headers.py`
* `warnings.py`
* `info.py`
* `last.py`

Each provider returns plain structured data and warnings. Providers do not print.

### `anchorforge/status/formatters/*`

Output-only modules:

* text formatter for human-readable output
* JSON formatter for stable machine-readable output

Formatters must not perform file I/O, network I/O, or business logic.

---

## Context Model

`StatusContext` should be a dataclass containing:

```python
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
address_utxo_store_path: Path | None
address_used_utxo_store_path: Path | None
address_tx_store_path: Path | None
warnings: list[StatusWarning]
```

The context should snapshot config values at creation time.

`--network` should affect only `effective_network`. It must not assign to
`Config.ACTIVE_NETWORK_NAME`, `Config.WOC_API_BASE_URL`, or any `Config.*_FILE`
attribute.

---

## Warning Model

Warnings should be represented consistently:

```python
StatusWarning(
    level="INFO|WARNING|CRITICAL|ERROR",
    message="...",
    context="..."
)
```

JSON output must emit warnings in this shape:

```json
{
  "level": "WARNING",
  "message": "UTXO store is missing",
  "context": "cache/wallet/utxo_store_test_abcdwxyz.json"
}
```

Missing optional local data is normally `WARNING`, not fatal.

Configuration failure may become exit code `3`.

---

## Path Resolution

Path resolution should use the current codebase conventions without mutating
state.

### Static Config Paths

Snapshot the current `Config` paths:

* `Config.AUDIT_LOG_FILE`
* `Config.BLOCK_HEADERS_FILE`
* `Config.TX_STORE_FILE`
* `Config.UTXO_STORE_FILE`
* `Config.USED_UTXO_STORE_FILE`

### Effective-Network Paths

For `--network`, compute status-local paths from base directories and effective
network rather than mutating `Config`.

### Address-Derived Paths

If `Config.UTXO_STORE_KEY_WIF` is available, derive the public worker address
and compute address-derived store paths using:

* `wallet_manager._get_filename_for_address`

This helper computes paths and is acceptable to call initially for compatibility.
It should later be wrapped by a public resolver API so status tooling does not
depend on a private wallet-manager helper. Status code must not call:

* `wallet_manager._ensure_store_exists`
* any `save_*` helper

### File Discovery Fallback

Current local state may exist in old or mixed locations. Providers should be
able to discover likely files by read-only glob patterns, for example:

* `cache/**/utxo_store_<network>_*.json`
* `cache/**/used_utxo_store_<network>_*.json`
* `database/**/tx_store_<network>_*.json`
* `output/audit_log_<network>.json`
* `cache/**/block_headers_<network>.json`

If both configured and discovered paths exist, providers should prefer
address-derived paths when a worker address is available, then configured paths,
then discovered single matches.

Glob discovery must never merge multiple candidate stores silently. If multiple
candidates exist, status output must report all candidates and pick one only by
deterministic, documented precedence. Ambiguous discovery should produce a
warning that includes the selected path, the selection reason, and the complete
candidate list.

---

## Provider Responsibilities

### Overview Provider

Returns:

* tool version
* AnchorForge library version
* config network
* CLI override network
* effective network
* config source path
* bank address
* working/UTXO address
* UTXO summary
* last local TXID
* integrity summary
* header readiness
* critical warnings
* help hint metadata

Missing optional data files must not fail overview.

### UTXO Provider

Reads active UTXO and used UTXO stores.

Returns:

* count
* total satoshis
* min/max
* dust count
* last created UTXOs
* last used UTXOs
* optional next-selection preview
* optional min/max value filtering

No remote comparison or repair is performed.

### TX Provider

Reads TX store as a primary source.

Returns:

* transaction count
* last TXIDs
* transaction details for local inspection
* local consistency markers against audit records when available

The TX store is independent local documentation, not merely a supplement to the
audit log.

### Integrity Provider

Reads audit log records.

Returns:

* record count
* last records
* filtering by keyword
* filtering by txid
* filtering by date range

The provider must tolerate malformed or missing logs with warnings.

### Headers Provider

Reads header cache only.

Returns:

* cache presence
* associated network
* header count
* readiness status
* coverage relative to confirmed audit records that contain block hashes

The provider must not fetch missing headers.

### Warnings Provider

Aggregates warnings from:

* context construction
* path resolution
* JSON readers
* provider consistency checks

Warnings should be grouped by severity in text output.

### Last Provider

Supports:

* `txid`
* `tx`
* `ir`
* `utxo-created`
* `utxo-used`
* `warnings`

Rules:

* default `n = 5`
* max `n = 100`
* newest first

### Info Provider

Supports local-only inspection:

* `info tx --txid <txid>`
* `info tx --rawtx <rawtx>`
* `info ir --id <log_id>`
* `info ir --keyword <keyword>`
* `info ir --txid <txid>`
* `info ir --date-from <date>`
* `info ir --date-to <date>`
* `info utxo --outpoint <txid:vout>`

No network lookup is performed.

---

## Formatting

### Text Formatter

Text output should be:

* deterministic
* section-based
* compact for overview
* explicit about missing or inconsistent local state
* free of secret values

### JSON Formatter

JSON output must be valid JSON only on stdout.

Top-level structure:

```json
{
  "meta": {},
  "data": {},
  "warnings": []
}
```

Rules:

* stable keys
* no human text outside JSON
* no secrets
* no ANSI color
* warnings represented as structured objects

---

## CLI Design

Supported commands:

```bash
af_status.py
af_status.py overview
af_status.py utxo
af_status.py tx
af_status.py integrity
af_status.py headers
af_status.py warnings
af_status.py last <type> [n]
af_status.py info <type> ...
```

Global options:

```bash
--network main|test
--format text|json
--detail basic|normal|full
-v
-vv
--no-color
```

Default command:

```bash
af_status.py
```

must behave like:

```bash
af_status.py overview
```

---

## Exit Codes

```text
0 success
1 runtime error
2 CLI misuse
3 configuration failure
```

Missing optional local data should normally produce exit code `0` with warnings.

---

## Forbidden Behaviors

`af_status` must not call:

* `wallet_manager._ensure_store_exists`
* `utils.ensure_json_file_exists`
* `wallet_manager.save_utxo_store`
* `wallet_manager.save_used_utxo_store`
* `wallet_manager.save_tx_store`
* `core_defs.save_audit_log`
* `BlockHeaderManager.save`
* `blockchain_service.sync_block_headers`
* blockchain API fetch, broadcast, or status functions

It must also avoid importing or invoking existing CLI scripts for business
logic, because those scripts configure logging, may validate wallet config, and
may have side effects.

---

## Testing Plan

The status implementation should satisfy:

* existing project tests
* `tests/test_behavioral_invariants.py`
* future focused status CLI/provider tests

The `AF-STATUS-*` invariant tests are allowed to remain `xfail` until the
status tool is implemented far enough to import and run. Once implementation is
complete, `AF-STATUS-*` tests must be converted from `xfail` to passing tests,
unless a documented requirement change justifies otherwise.

Important tests:

* read-only state snapshot tests
* no-remote-call tests
* JSON stdout contract tests
* network override isolation tests
* missing-data overview tests
* forbidden-helper tests
* secret redaction tests
