# AnchorForge CLI Tool Manual

This document serves as a technical reference for the Command Line Interface (CLI) tools provided with **AnchorForge**. These tools allow you to anchor data, synchronize block headers, manage your wallet/UTXOs, and verify audit trails.

> **Note:** All tools require a properly configured `.env` file in the `local_config` directory. Ensure your environment is set up (see `quickstart.md`) before running these commands.

---

## 1. Core Tools

### `af_anchor.py`
**Purpose:** The main entry point for logging (anchoring) a single audit event to the Bitcoin SV blockchain. It creates a transaction containing the hash (and optional signatures/data) of your input.

**Usage:**
```bash
python af_anchor.py [OPTIONS] --data <STRING> | --file <PATH>
```

**Arguments:**

| Argument | Description | Required |
| :--- | :--- | :--- |
| `--data <string>` | Raw string content to anchor (Mode: `embedded`). Mutually exclusive with `--file`. | Yes* |
| `--file <path>` | Path to a file to hash and anchor (Mode: `by_reference`). Mutually exclusive with `--data`. | Yes* |
| `--record-note <text>` | A generic note stored in the local audit log (JSON). Supports `@filename` syntax. | No |
| `--transaction-note <text>` | A note embedded into the blockchain transaction (OP_RETURN). Supports `@filename`. | No |
| `--keyword <tag>` | A keyword to categorize the event (Default: `general-event`). | No |
| `--include <list>` | Comma-separated list of components to include in the payload. Options: `hash`, `ec`, `x509`, `data`, `reference`, `basereference`. (Default: `hash,ec,x509`). | No |
| `--dry-run` | Simulates the process without broadcasting or saving changes. | No |
| `--no-broadcast` | Updates local stores/logs but does **not** broadcast the transaction to the network. | No |
| `--mainnet` | Safety flag required when `NETWORK=main` is set in config. | Conditional |

**Examples:**

* **Anchor a string (Default: Hash + EC Sig + Certificate):**
    ```bash
    python af_anchor.py --data "System Health OK" --keyword "health-check"
    ```

* **Anchor a file (Hash only, minimal privacy):**
    ```bash
    python af_anchor.py --file ./reports/monthly_pdf.pdf --include "hash" --keyword "reports"
    ```

* **Embed small data on-chain:**
    ```bash
    python af_anchor.py --data "Critical Config" --include "hash,ec,data"
    ```

---

### `af_verify.py`
**Purpose:** Verifies the integrity and blockchain inclusion of records stored in the audit log. It performs local hash checks, signature verification, and SPV (Merkle Proof) validation.

**Usage:**
```bash
python af_verify.py --log-file <PATH> --output-file <PATH> [OPTIONS]
```

**Arguments:**

| Argument | Description | Required |
| :--- | :--- | :--- |
| `--log-file <path>` | Path to the audit log JSON file to verify. | Yes |
| `-o, --output-file <path>` | Path to save the verification results. | Yes |
| `--network <main\|test>` | Overrides the network configuration for block header validation. | No |
| `--id <log_id>` | Verify a specific record ID only. | No |
| `-k, --keyword <tag>` | Verify only records matching this keyword. | No |
| `--data-dir <path>` | Base directory to search for referenced files if original path is missing. | No |
| `--alt-file <path>` | Alternative file path to use for hash verification. | No |

**Granular Checks (Flags):**
If no flags are provided, **all** checks are run by default.
* `--check-tx-consistency`: Verify stored TXID matches raw transaction.
* `--check-spv-proof`: Verify Merkle Path against Block Headers (SPV).
* `--check-ec-hash`: Verify local content hash matches on-chain EC hash.
* `--check-ec-signature`: Verify ECDSA signature.
* `--check-x509-hash`: Verify local content hash matches on-chain X.509 hash.
* `--check-x509-signature`: Verify X.509 certificate signature.

**Example:**
```bash
python af_verify.py --log-file output/audit_log_test.json --output-file output/audit_report.json --check-spv-proof
```

---

### `af_monitor.py`
**Purpose:** Monitors pending transactions in the local audit log. Once a transaction is confirmed on the blockchain, it updates the log with the block height, block hash, and Merkle proof.

**Usage:**
```bash
python af_monitor.py [OPTIONS]
```

**Arguments:**
* `-d, --duration <minutes>`: Run the monitor for a specific duration and then exit. If omitted, runs continuously.

**Example:**
```bash
python af_monitor.py --duration 60
```

---

### `af_sync.py`
**Purpose:** Synchronizes block headers from the network to a local cache. This cache is required for SPV verification (`af_verify.py`).

**Usage:**
```bash
python af_sync.py [MODE] [OPTIONS]
```

**Modes (Mutually Exclusive):**
* `--last <N>`: Sync the last N blocks from the chain tip.
* `--range <START-END>`: Sync a specific range (e.g., `1000-2000`).
* `--block <HEIGHT>`: Sync a single block.
* `--blocks <LIST>`: Sync a comma-separated list of heights (e.g., `100,205,300`).
* `--convert <FILE>`: Offline mode to convert/minimize an existing header file.

**Options:**
* `--output <file>`: Custom output filename.
* `--minimal-info`: Store only minimal data (Hash, Merkle Root, Time, PrevHash) to save space.
* `--network <main|test>`: Override network config.

**Example:**
```bash
python af_sync.py --last 1000 --minimal-info
```

---

## 2. Management & Wallet Tools

### `af_utxo_manager.py`
**Purpose:** Analyzes, repairs, and manages the local UTXO (Unspent Transaction Output) cache. Essential for keeping the wallet in sync with the blockchain to prevent "Missing Input" errors.

**Usage:**
```bash
python af_utxo_manager.py <COMMAND> [OPTIONS]
```

**Global Options:**
* `--file <path>`: Path to a specific UTXO JSON file.
* `--address <addr>`: Automatically resolves file paths based on the address.
* `--network <main|test>`: Override network config.

**Commands:**

1.  **`stats`**: Show statistics (count, total value, dust analysis).
    ```bash
    python af_utxo_manager.py stats --address <YOUR_ADDR>
    ```
2.  **`compare`**: Compare local cache with the remote API (WhatsOnChain). Shows stale or new UTXOs.
    ```bash
    python af_utxo_manager.py compare --address <YOUR_ADDR>
    ```
3.  **`repair`**: Smart repair. Removes stale UTXOs and adds new ones found on-chain.
    ```bash
    python af_utxo_manager.py repair --address <YOUR_ADDR>
    ```
4.  **`full-repair`**: Completely rebuilds the cache from the API.
    ```bash
    python af_utxo_manager.py full-repair --address <YOUR_ADDR>
    ```
5.  **`check <txid:vout>`**: Check status of a specific UTXO.
6.  **`add <txid:vout:sats>`**: Manually add a UTXO.
7.  **`remove <txid:vout>`**: Manually remove a UTXO.

---

### `main_wallet_setup.py`
**Purpose:** Utilities for wallet initialization and UTXO splitting ("Utxolets"). Useful for creating many small UTXOs to allow parallel transaction processing.

**Usage:**
```bash
python main_wallet_setup.py [OPTIONS]
```

**Arguments:**
* `--sync`: Synchronize the UTXO store (wrapper around manager).
* `--create-utxolets <SIZE> <NUMBER>`: Splits funds from the Bank Address into `<NUMBER>` small UTXOs of `<SIZE>` satoshis each.
* `--mainnet`: Safety flag for mainnet operations.

**Example (Create 50 UTXOs of 2000 sats each):**
```bash
python main_wallet_setup.py --create-utxolets 2000 50
```

---

## 3. Utility Tools

### `af_drain_bank.py`
**Purpose:** Sweeps **all** funds from the configured Bank Address to a target address. Useful for retrieving funds after testing.

**Usage:**
```bash
python af_drain_bank.py <TARGET_ADDRESS>
```

### `af_fill_bank.py`
**Purpose:** Transfers funds from the configured `TEMPORARY_SOURCE_FUNDS_KEY_WIF` to the Bank Address.

**Usage:**
```bash
python af_fill_bank.py
```
