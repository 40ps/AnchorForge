# Examples & Stress-Testing

This document showcases how to use AnchorForge v0.2 through practical examples, ranging from manual single-point notarization to automated high-frequency batch logging.

---

## 1. Manual Single-Point Anchor (af_anchor.py)

The `af_anchor.py` tool serves as the fundamental example of how to interact with the protocol manually. It is ideal for one-off notarizations of files or status messages.

### Example: Notarizing a Local File
If you have a document (e.g., `contract.pdf`) and want to anchor its unique SHA-256 hash to prove its state at this moment:

```bash
python af_anchor.py --file "./contract.pdf" --keyword "legal-notarization" --record-note "Final version signed."
```

### Example: Custom TLV Tags
You can decide which cryptographic proofs to include on-chain. For a minimal footprint (Hash only):

```bash
python af_anchor.py --data "System Check Pass" --include hash --keyword "maintenance"
```

---

## 2. Automated ISS Tracking (main_batch_iss.py)

Located in the `/examples` directory, this script demonstrates how AnchorForge integrates with live external data streams.

### Key Features
- **Real-Time Data:** Fetches coordinates (latitude, longitude) and velocity from the *WhereTheISS.at* REST API.
- **High-Frequency Logging:** Designed to show how many small transactions can be broadcast in sequence using the "Worker/UTXOlet" model.
- **Structured Anchoring:** Logs full JSON objects containing altitude, visibility, and server timestamps.

### Usage
To log 20 consecutive location data points:
```bash
python examples/main_batch_iss.py --count 20 --keyword "iss-tracking-session-A"
```

---

## 3. Financial Audit Trails (main_batch_coingecko.py)

This example illustrates the creation of verifiable financial data trails using the CoinGecko price feed.

### Key Features
- **API Resilience:** Implements a mandatory 10-second delay between requests to comply with free-tier API rate limits.
- **Batch Persistence:** Uses a status file (`runtime/coingecko_batch_status.json`) to track progress. If the process is interrupted, running the command again will automatically resume from the last successful log.
- **Price Anchoring:** Records the BSV/EUR exchange rate and the server-side "last updated" timestamp for full auditability.

### Usage
To start a batch of 50 price logs:
```bash
python examples/main_batch_coingecko.py --count 50 --keyword "price-audit-01"
```

---

## 4. Simulation and Safety Patterns

All examples support "Safe Modes" to allow developers to test logic without spending actual BSV or updating permanent records.

### Dry Run
Builds and signs the transaction, but **does not** broadcast it to the network and **does not** save anything to local JSON stores.
```bash
python examples/main_batch_iss.py --count 5 --dry-run
```

### Simulation Mode (--no-broadcast)
Updates all local stores (Audit Log, UTXO Cache) and creates valid transactions, but **skips the blockchain broadcast**. It uses `.sim.json` files to keep simulation data separate from real data.
```bash
python examples/main_batch_iss.py --count 5 --no-broadcast
```

### Process Control
For long-running batches, use the `control_process.py` tool in a separate terminal to manage the execution:
```bash
# Pause the ISS tracking
python control_process.py iss pause

# Resume the tracking
python control_process.py iss resume

# Stop the process gracefully
python control_process.py coingecko stop
```
