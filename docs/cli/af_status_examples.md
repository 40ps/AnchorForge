# af_status Examples

These examples assume commands are run from the repository root with the
project virtual environment.

## Overview

```bash
.venv/bin/python af_status.py
.venv/bin/python af_status.py overview
.venv/bin/python af_status.py overview --format json
```

Expected behavior:

- prints local status
- reports missing optional files as warnings
- does not create or repair state

## Inspect UTXOs

```bash
.venv/bin/python af_status.py utxo
.venv/bin/python af_status.py utxo --next 3
.venv/bin/python af_status.py utxo --min-value 100 --max-value 1000 --format json
```

Use `--next` for a local selection preview. This is not a spend operation.

## Inspect the TX Store

```bash
.venv/bin/python af_status.py tx
.venv/bin/python af_status.py tx --detail full --format json
```

The TX store is treated as local transaction documentation. Raw transaction
payloads are summarized, not printed.

## Inspect Integrity Records

```bash
.venv/bin/python af_status.py integrity
.venv/bin/python af_status.py integrity --keyword invoice
.venv/bin/python af_status.py integrity --txid <txid>
.venv/bin/python af_status.py integrity --date-from 2026-01-01
.venv/bin/python af_status.py integrity --date-from 2026-01-01 --date-to 2026-01-31
```

Keyword filters use case-insensitive substring matching.

## Inspect Header Readiness

```bash
.venv/bin/python af_status.py headers
.venv/bin/python af_status.py headers --format json
```

`missing` means no readable local cache is available.

`incomplete` means local confirmed audit records refer to block hashes that are
not covered by the local cache.

`ready` means the local cache covers all locally known confirmed audit records
with block references.

## Last Queries

```bash
.venv/bin/python af_status.py last txid
.venv/bin/python af_status.py last tx 10
.venv/bin/python af_status.py last ir
.venv/bin/python af_status.py last utxo-created
.venv/bin/python af_status.py last utxo-used
.venv/bin/python af_status.py last warnings
```

The optional count defaults to `5` and is capped at `100`.

## Info Queries

```bash
.venv/bin/python af_status.py info tx --txid <txid>
.venv/bin/python af_status.py info tx --rawtx <rawtx>
.venv/bin/python af_status.py info ir --id <log_id>
.venv/bin/python af_status.py info ir --keyword anchor
.venv/bin/python af_status.py info ir --txid <txid>
.venv/bin/python af_status.py info ir --date-from 2026-01-01
.venv/bin/python af_status.py info utxo --outpoint <txid:vout>
```

Not-found objects return warnings, not remote lookups.

## Missing File Example

If a header cache is missing, JSON output may contain:

```json
{
  "level": "WARNING",
  "message": "Local data file is missing",
  "context": "cache/public/block_headers_test.json"
}
```

The command still exits successfully when the missing file is optional.

## JSON Contract Example

All JSON commands use the same top-level shape:

```json
{
  "meta": {
    "command": "overview"
  },
  "data": {},
  "warnings": []
}
```

Human text is not mixed into JSON stdout.

## Local-Only Verification

These commands are safe local inspection commands:

```bash
.venv/bin/python af_status.py overview --format json
.venv/bin/python af_status.py headers --format json
.venv/bin/python af_status.py info tx --txid deadbeef --format json
```

They do not contact WhatsOnChain or other remote services.
