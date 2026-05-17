# af_status CLI Guide

`af_status.py` is a read-only inspection tool for local AnchorForge state.

It is designed for developers, auditors, and operators who need to understand
the current local installation without creating transactions, synchronizing
headers, repairing files, or contacting remote blockchain APIs.

## Safety Model

`af_status.py` is local-only in the current implementation.

It reads local configuration and state files, then reports summaries and
warnings. It does not:

- create transactions
- sign transactions
- broadcast transactions
- fetch remote transactions or headers
- synchronize missing headers
- repair or normalize local JSON files
- write local state
- print private keys, WIFs, seed phrases, or API keys

Current AnchorForge configuration loading may create configured runtime
directories as part of existing project behavior. `af_status.py` does not add
additional writes of its own.

## Usage

```bash
.venv/bin/python af_status.py [global options] [command] [command options]
```

Default command:

```bash
.venv/bin/python af_status.py
```

is equivalent to:

```bash
.venv/bin/python af_status.py overview
```

## Global Options

```text
--network main|test
--format text|json
--detail basic|normal|full
-v
-vv
--no-color
```

`--network` computes an effective status network for file selection. It does
not mutate global `Config` values.

`--format json` emits JSON only on stdout:

```json
{
  "meta": {},
  "data": {},
  "warnings": []
}
```

Warnings use this shape:

```json
{
  "level": "WARNING",
  "message": "Local data file is missing",
  "context": "cache/public/block_headers_test.json"
}
```

`--no-color` is accepted for CLI compatibility. Version 1 emits no ANSI color.

## Commands

### overview

```bash
.venv/bin/python af_status.py overview
.venv/bin/python af_status.py overview --format json
```

Reports a compact local dashboard:

- tool version
- AnchorForge package version
- config network
- CLI network override
- effective network
- config source path
- bank address
- working address, when safely available
- UTXO summary
- last local TXID
- TX summary
- integrity summary
- header readiness
- critical warnings
- selected local source paths

Missing optional local files produce warnings and partial output.

### utxo

```bash
.venv/bin/python af_status.py utxo
.venv/bin/python af_status.py utxo --next 10
.venv/bin/python af_status.py utxo --min-value 100 --max-value 1000
```

Reads local active and used UTXO stores.

Reports:

- active UTXO count, total, min/max, dust count
- used UTXO count, total, min/max, dust count
- newest created UTXOs
- newest used UTXOs
- optional next-selection preview
- selected local source paths

No UTXO repair, refetch, or rebalance is performed.

### tx

```bash
.venv/bin/python af_status.py tx
.venv/bin/python af_status.py tx --format json
```

Reads the local TX store as an independent documentation source.

Reports:

- selected TX store path
- transaction count
- store address and network metadata, when present
- last TXID and timestamp
- newest TXIDs
- safe transaction summaries

Raw transaction payloads are not printed. The summary reports only metadata
such as raw hex length and whether raw transaction data is present.

### integrity

```bash
.venv/bin/python af_status.py integrity
.venv/bin/python af_status.py integrity --keyword invoice
.venv/bin/python af_status.py integrity --txid <txid>
.venv/bin/python af_status.py integrity --date-from 2026-01-01
.venv/bin/python af_status.py integrity --date-to 2026-01-31T23:59:59+00:00
```

Reads local audit/integrity logs.

Reports:

- selected audit log path
- record count
- filtered count
- last log ID
- last timestamp
- last keyword
- last TXID
- newest safe record summaries

Keyword matching is case-insensitive substring matching.

Date filtering is best-effort. If a filter or record timestamp cannot be
parsed, the provider reports structured warnings rather than modifying data.

### headers

```bash
.venv/bin/python af_status.py headers
.venv/bin/python af_status.py headers --format json
```

Reads the local header cache and local audit log.

Reports:

- selected header cache path
- selected audit log path
- cache present/readable flags
- header count
- detected network, when available
- readiness state

Readiness values:

- `missing`: no readable local header cache
- `incomplete`: cache exists but does not cover all locally known confirmed
  audit records with block references
- `ready`: cache exists and covers all locally known confirmed audit records
  with block references

The command never triggers sync, verification, header fetches, or remote API
calls.

### last

```bash
.venv/bin/python af_status.py last txid
.venv/bin/python af_status.py last tx 10
.venv/bin/python af_status.py last ir
.venv/bin/python af_status.py last utxo-created
.venv/bin/python af_status.py last utxo-used
.venv/bin/python af_status.py last warnings
```

Supported types:

- `txid`
- `tx`
- `ir`
- `utxo-created`
- `utxo-used`
- `warnings`

Rules:

- default `n` is `5`
- maximum `n` is `100`
- output is newest first
- invalid `n` is CLI misuse

The command reuses implemented provider results rather than performing separate
file reads.

### info

```bash
.venv/bin/python af_status.py info tx --txid <txid>
.venv/bin/python af_status.py info tx --rawtx <rawtx>

.venv/bin/python af_status.py info ir --id <log_id>
.venv/bin/python af_status.py info ir --keyword <keyword>
.venv/bin/python af_status.py info ir --txid <txid>
.venv/bin/python af_status.py info ir --date-from <date>
.venv/bin/python af_status.py info ir --date-to <date>

.venv/bin/python af_status.py info utxo --outpoint <txid:vout>
```

`info` performs local object inspection only.

For `info tx --rawtx`, the tool computes a transaction ID from valid local raw
hex and returns a local raw transaction summary. It does not decode through
external services and does not broadcast.

Object misses are reported as structured warnings.

Malformed queries return CLI misuse.

## Missing Files and Warnings

Optional local state files may be absent in a fresh checkout or read-only
verification setup.

Examples:

- missing UTXO store
- missing used UTXO store
- missing TX store
- missing audit log
- missing header cache
- malformed JSON
- unexpected top-level JSON type
- ambiguous discovered candidates

These conditions produce warnings and partial output. They should not create
files or cause automatic repair.

## Troubleshooting

### JSON parsing fails

Use `--format json` on the command itself:

```bash
.venv/bin/python af_status.py overview --format json
```

Stdout should contain JSON only. Warnings are embedded inside the JSON object.

### Header readiness is missing

This usually means the local header cache file is absent or unreadable. Run the
separate sync tooling explicitly if you intend to populate headers. `af_status`
will not sync them for you.

### Transaction or UTXO not found

`info` only searches local stores. It does not query blockchain explorers or
remote APIs.

### Network mismatch

Use:

```bash
.venv/bin/python af_status.py overview --network main
```

The network override changes status file selection only. It does not mutate
global configuration.
