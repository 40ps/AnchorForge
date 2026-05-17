# AnchorForge Status Tool Specification

## af_status.py

---

## 1. Purpose

`af_status.py` is a command-line tool that provides a comprehensive, read-only overview and inspection interface for the local state of an AnchorForge installation.

It serves three primary purposes:

1. **Status Dashboard** – Present the current system state in a compact and human-readable way
2. **Exploration Tool** – Allow users to inspect transactions, UTXOs, and integrity records
3. **Analysis Tool** – Support debugging, auditing, and understanding of system behavior

The tool is designed for:

* developers
* technically inclined users
* auditors
* demonstration and learning scenarios

---

## 2. Scope

The tool operates primarily on **local data sources** and supports **optional remote comparison**.

It covers the following domains:

* runtime configuration
* network context
* wallet and address state
* UTXO state
* transaction storage
* integrity/audit logs
* header cache (SPV readiness)
* system warnings and inconsistencies

---

## 3. Design Principles

### 3.1 Read-Only

The tool must never modify local data.

### 3.2 Off-Chain First

Local data is the primary source of truth.
Remote data is only used explicitly.

### 3.3 Fail Soft, Not Silent

The tool should:

* provide as much information as possible
* never silently ignore issues
* clearly report missing or inconsistent data

### 3.4 Separation of Concerns

* CLI logic
* business logic
* formatting

must be separated.

### 3.5 Deterministic Output

Output must be:

* stable
* predictable
* consistent across runs

---

## 4. Functional Requirements

---

### 4.1 Overview (Default Mode)

Command:

```bash
af_status.py
af_status.py overview
```

Must display:

* tool version
* AnchorForge library version
* config network
* CLI override network
* effective network
* config source (path to `.env`)
* bank address
* working/UTXO address
* UTXO summary:

  * count
  * total
  * min/max
  * dust count
* last local TXID
* integrity summary:

  * record count
  * last log_id
  * timestamp
  * keyword (if available)
* header readiness:

  * ready / incomplete / missing
* critical warnings
* hint to help/subcommands

---

### 4.2 UTXO

Command:

```bash
af_status.py utxo
```

Capabilities:

* UTXO summary
* last created UTXOs
* last used UTXOs
* selection:

  * `--next [n]`
  * `--min-value`
  * `--max-value`

---

### 4.3 TX (Transaction Store)

Command:

```bash
af_status.py tx
```

The TX store is a **primary data source**.

It must support:

* TX count
* last TXIDs
* TX inspection
* consistency analysis with audit logs

The TX store is considered:

> an independent documentation source of transactions, even if audit logs are missing or corrupted.

---

### 4.4 Integrity Records (Audit Logs)

Command:

```bash
af_status.py integrity
```

Capabilities:

* record count
* last records
* filtering:

  * by keyword
  * by txid
  * by date range

---

### 4.5 Headers (SPV Readiness)

Command:

```bash
af_status.py headers
```

Must provide:

* header cache presence
* associated network
* readiness status
* coverage relative to integrity records

---

### 4.6 Warnings

Command:

```bash
af_status.py warnings
```

Displays:

* critical warnings
* all warnings grouped by severity

---

### 4.7 Info Queries

Command:

```bash
af_status.py info <type>
```

Supported:

#### TX

```bash
af_status.py info tx --txid <txid>
af_status.py info tx --rawtx <rawtx>
```

#### Integrity Records

```bash
af_status.py info ir --id <log_id>
af_status.py info ir --keyword <keyword>
af_status.py info ir --txid <txid>
af_status.py info ir --date-from <date>
af_status.py info ir --date-to <date>
```

Keyword matching:

* default: case-insensitive substring match
* optional: exact match (future)

#### UTXO

```bash
af_status.py info utxo --outpoint <txid:vout>
```

---

### 4.8 Last Queries

Command:

```bash
af_status.py last <type> [n]
```

Supported:

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

---

## 5. CLI Design

* subcommand-based

* global options:

  * `--network`
  * `--format`
  * `--detail`
  * `--no-color`

* verbosity:

  * `-v`, `-vv` mapped to detail levels

---

## 6. Data Sources

### 6.1 Primary Sources

* `.env` (configuration)
* UTXO store
* TX store
* audit logs
* header cache

### 6.2 Priority

1. CLI override
2. `.env`
3. data files (validation only)

### 6.3 Remote

* optional
* explicit only
* clearly marked

---

## 7. Consistency Rules

* no silent corrections
* mismatches produce warnings
* all inconsistencies must be visible

---

## 8. Error Handling

### Severity Levels

* INFO
* WARNING
* CRITICAL WARNING
* ERROR

### Exit Codes

| Code | Meaning        |
| ---- | -------------- |
| 0    | success        |
| 1    | runtime error  |
| 2    | CLI misuse     |
| 3    | config failure |

---

## 9. Output Format

### Text (default)

* section-based layout
* deterministic ordering
* compact overview

### JSON

Structure:

```json
{
  "meta": {},
  "data": {},
  "warnings": []
}
```

Rules:

* stable keys
* no dynamic structures
* no secrets

---

## 10. Architecture

### 10.1 Structure

* CLI layer
* provider layer
* formatter layer

### 10.2 Providers

Each domain provides:

```python
get_<domain>_status(context, detail)
```

### 10.3 Context

Central object containing:

* network resolution
* config
* paths

### 10.4 Path Resolution

All paths must be resolved centrally.
No hardcoded file paths.

---

## 11. Security Constraints

* never expose private keys
* no secrets in output
* only derived/public data allowed

---

## 12. Future Extensions

### 12.1 Wallet Abstraction

The tool must not depend on WIF-based key handling.

Future support for BRC-100 or other wallet systems must be possible via abstraction layers.

### 12.2 UI Integration

The data model must be reusable for graphical interfaces.

### 12.3 Additional Tools

The architecture should support:

* diagnostic tools
* repair tools
* transaction management tools

---

## 13. Non-Goals

* no transaction creation
* no signing
* no state mutation
* no automatic repair

---

## 14. Summary

`af_status.py` is a structured, extensible, and robust inspection tool for AnchorForge.

It provides:

* a clear system overview
* deep inspection capabilities
* consistent CLI behavior
* a foundation for future tools and UI integration

---
## Behavioral Constraints

This specification may be complemented by documents in:
docs/standards/


This tool must comply with the global invariants defined in:

docs/standards/behavioral_invariants.md


Related:
prompts/codegen/af_status_codegen.md
