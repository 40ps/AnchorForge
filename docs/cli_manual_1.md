# AnchorForge CLI Reference Manual

This document provides a comprehensive reference for the Command Line Interface (CLI) tools included in the AnchorForge (v0.2) suite. These tools allow you to anchor data, manage UTXOs, synchronize block headers, and monitor the audit status.

**Note:** All scripts act according to the network defined in your `.env` file (`NETWORK=test` or `NETWORK=main`). For Mainnet operations, many scripts require an explicit `--mainnet` safety flag.

---

## 1. Core: Anchoring Data (`af_anchor.py`)

The primary tool for creating audit records and anchoring them to the Bitcoin SV blockchain. It creates the OP_RETURN payload, updates local stores, and broadcasts the transaction.

**Usage:**
`python af_anchor.py [ARGUMENTS]`

### Required Arguments (Mutually Exclusive)
You must provide exactly one of the following:

* **--data <STRING>**
    * Embeds the provided string directly into the audit record ("embedded" mode).
    * Example: `--data "System Backup 2024-10-01"`
* **--file <PATH>**
    * Anchors a file by reference ("by_reference" mode). The tool hashes the file content locally; the file content itself is not stored on-chain unless specified via `--include`.
    * Example: `--file "./reports/audit_final.pdf"`

### Optional Arguments

* **--record-note <STRING>**
    * Adds a human-readable note to the local JSON audit log entry.
    * Can be a direct string or a file path prefixed with `@` (e.g., `@notes.txt`).
* **--transaction-note <STRING>**
    * Adds a plaintext note to the OP_RETURN payload (visible on-chain).
    * Can be a direct string or a file path prefixed with `@`.
* **--keyword <STRING>**
    * A keyword or tag to categorize the event (default: "general-event").
* **--include <LIST>**
    * Comma-separated list of components to include in the OP_RETURN payload.
    * **Options:**
        * `hash`: The SHA-256 hash of the data (Standard).
        * `ec`: Elliptic Curve Signature (Standard).
        * `x509`: X.509 Certificate and Signature (Standard).
        * `data`: Pushes the raw data on-chain (Warning: Size limits apply).
        * `reference`: Pushes the full file path string.
        * `basereference`: Pushes only the filename string.
    * **Default:** `hash,ec,x509`
* **--dry-run**
    * Simulates the transaction creation without updating local stores or broadcasting. Useful for checking fees and payload structure.
* **--no-broadcast**
    * Updates local stores and generates the transaction but acts as if the broadcast succeeded without sending it to the network. Useful for offline testing or separate broadcasting.
* **--mainnet**
    * **Required** if `.env` is set to `NETWORK=main`. A safety flag to prevent accidental spending of real BSV.

---

## 2. Infrastructure: Network & Sync

### Block Header Synchronization (`af_sync.py`)
Synchronizes block headers from WhatsOnChain to the local cache. This is strictly required for SPV (Simplified Payment Verification) proofs.

**Usage:**
`python af_sync.py [ARGUMENTS]`

**Arguments:**

* **--last <N>**
    * Syncs the last N blocks from the chain tip.
    * Example: `--last 2000` (Recommended for setting up a fresh environment).
* **--block <HEIGHT>**
    * Syncs a single specific block height.
* **--range <START-END>**
    * Syncs a range of blocks.
    * Example: `--range 800000-800100`
* **--blocks <LIST>**
    * Syncs a specific list of comma-separated block heights.
    * Example: `--blocks 100,105,110`
* **--output <FILE>**
    * Writes headers to a custom output file instead of the default `database/block_headers_<NET>.json`.
* **--minimal-info**
    * Stores only the absolute minimum header data required for SPV to save space.

### Transaction Monitor (`af_monitor.py`)
Monitors locally created transactions ("broadcasted" state) for network confirmation. Once confirmed, it fetches the Merkle Proof (TSC format preferred) and updates the audit log status to "confirmed".

**Usage:**
`python af_monitor.py [ARGUMENTS]`

**Arguments:**

* **--duration <MINUTES>**
    * Runs the monitor for a specific duration in minutes and then exits.
    * If omitted, the monitor runs continuously until stopped (Ctrl+C or stop flag).

---

## 3. Wallet & UTXO Management (`af_utxo_manager.py`)

A critical tool for managing the internal wallet state, repairing desynchronized UTXO sets, and analyzing wallet health.

**Usage:**
`python af_utxo_manager.py [GLOBAL_ARGS] [COMMAND] [COMMAND_ARGS]`

**Global Arguments:**

* **--address <ADDRESS>**
    * Specifies the wallet address to manage. The tool resolves the corresponding filenames automatically.
* **--file <PATH>**
    * Directly targets a specific UTXO JSON file (alternative to `--address`).
* **--network <main|test>**
    * Overrides the configuration in `.env`.

**Commands:**

* **stats**
    * Displays statistics: Total UTXO count, total value, dust count, and average value.
* **compare**
    * Compares the local UTXO file against the blockchain (WhatsOnChain API).
    * Reports "Stale" (local but spent) and "New" (on-chain but missing locally) UTXOs.
* **check <TXID:VOUT>**
    * Checks the status of a specific UTXO in both the local store and on the blockchain.
* **repair**
    * **Recommended maintenance command.**
    * Smart repair: Removes stale UTXOs (archiving them to `*_invalid.json`) and fetches new UTXOs from the API. Updates the Transaction Store with raw hex data for new inputs.
* **full-repair**
    * Wipes the local UTXO list and re-downloads all unspent outputs from the API. Updates the Transaction Store.
* **add <TXID:VOUT:SATS>**
    * Manually adds a UTXO to the local store (validates against API first).
* **remove <TXID:VOUT>**
    * Manually removes a UTXO from the local store.

---

## 4. Analysis & Process Control

### Audit Log Analyzer (`af_log_analyzer.py`)
Analyzes the integrity and format of the `audit_log_<NET>.json` file. It specifically checks for valid Merkle Proofs (Legacy vs. TSC format) and summarizes record statuses.

**Usage:**
`python af_log_analyzer.py --log-file <PATH> --network <main|test>`

### Process Controller (`control_process.py`)
Manages long-running background processes (like the monitor or batch scripts) using flag files in the `runtime/` directory.

**Usage:**
`python control_process.py <PROCESS_NAME> <ACTION>`

**Arguments:**

* **PROCESS_NAME**: e.g., `monitor`, `coingecko`, `iss`.
* **ACTION**:
    * `pause`: Creates a pause flag; the process pauses execution loop.
    * `resume`: Removes the pause flag.
    * `stop`: Creates a stop flag; the process terminates gracefully.

---

## 5. Utility Scripts

### Drain Bank (`af_drain_bank.py`)
Sweeps all funds from the configured Bank Address to a specified target address. Useful for retrieving funds after testing.

**Usage:**
`python af_drain_bank.py <TARGET_ADDRESS>`

### Environment Setup (`af_setup_fresh_environment.py`)
A helper script for new installations. It checks directory structures, generates a unique key pair (if none exists), and triggers an initial UTXO repair and header sync.

**Usage:**
`python af_setup_fresh_environment.py`

### Batch Examples
Included in the root or `examples/` folder for demonstration:

* **main_batch_coingecko.py**: Fetches BSV price data and anchors it.
    * Args: `--count`, `--reset`, `--backup`.
* **main_batch_iss.py**: Fetches ISS satellite location and anchors it.
    * Args: `--count`, `--reset`.