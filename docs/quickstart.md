# Quickstart Guide

This guide will walk you through setting up AnchorForge v0.2 and creating your first blockchain-anchored audit record.

## 1. Prerequisites
- **Python 3.10+**
- **PIP** (Python Package Manager)
- A small amount of **BSV** (Bitcoin SV) for network fees. (Testnet coins are available for free via community faucets).

## 2. Initial Setup

### Clone and Install
First, clone the repository and install the required dependencies:
```bash
git clone [https://github.com/](https://github.com/)40ps/AnchorForge.git
cd AnchorForge
pip install -r requirements.txt
```
Copy `local_config/.env.template` to `local_config/.env` and fill in your credentials. ENSURE .env (or any file with secrets) is never commited. Ensure .gitignore contains all files with secrets.

### Initialize the Environment

Run the automated setup script to create the necessary directory structure (`/cache`, `/database`, `/runtime`, etc.) and generate your first local keys if none exist:

```bash
python af_setup_fresh_environment.py

```

*Note: If a new key is generated, the script will provide a WIF (Private Key). You must add this to your `local_config/.env` file manually.*

## 3. Funding the "Bank"

AnchorForge uses a two-tier wallet system to ensure efficiency and prevent transaction chaining issues:

1. **The Bank Address:** Holds your main funds.
2. **The Worker Address:** Holds many small "UTXOlets" used for individual audit transactions.

### Step A: Load the Bank

Send a small amount of BSV to the `BANK_ADDRESS` defined in your `.env`.

### Step B: Create UTXOlets

To perform high-frequency logging, you need to split your bank funds into many small Unspent Transaction Outputs (UTXOs). Use the setup tool to create them:

```bash
# Example: Create 50 UTXOs of 1000 satoshis each
python anchorforge/main_wallet_setup.py --create-utxolets 1000 50

```

**Why this matters:**

* **Concurrency:** Each UTXO can be spent independently. If you have 50 UTXOs, you can anchor 50 events without waiting for the previous transaction to be mined.
* **Dust Limit:** Ensure your UTXO size is above the "dust limit" (typically 546 satoshis) to ensure they are accepted by miners.

## 4. Your First Anchor

Now you are ready to anchor data. Use `af_anchor.py` to create an audit record:

```bash
# Anchoring a simple string (Embedded Mode)
python af_anchor.py --data "System Health: OK" --keyword "health-check"

# Anchoring a file (By Reference Mode)
python af_anchor.py --file "./report.pdf" --keyword "legal-doc"

```

## 5. Verification

To verify that your records are actually anchored and the hashes match:

### Sync Block Headers

First, ensure your local cache of the blockchain headers is up to date:

```bash
python af_sync.py --last 100

```

### Run the Monitor

Start the monitor to fetch Merkle Proofs for your transactions once they are confirmed by miners:

```bash
python af_monitor.py --duration 10

```

### Verify Integrity

Once the monitor marks a record as "confirmed", you can run the verifier logic to check cryptographic signatures and blockchain inclusion (SPV).

---

**Next Steps:**

* Explore advanced TLV tagging in the [CLI Manual](docs/cli_manual.md).
* Learn about the protocol internals in [Architecture](architecture.md).
