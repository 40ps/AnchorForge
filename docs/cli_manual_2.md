# CLI Tool Manual - AnchorForge v0.2

This document provides a detailed reference for all Command Line Interface (CLI) tools.

--------------------------------------------------------------------------------
1. af_anchor.py
--------------------------------------------------------------------------------
The primary tool for creating audit records and anchoring them to the Bitcoin SV blockchain.

Usage:
  python af_anchor.py [DATA_SOURCE] [OPTIONS]

Data Sources (Choose one):
  --data "string"    Direct string to be anchored (Embedded Mode).
  --file "./path"    Path to a file. The file is hashed and the hash is anchored 
                     (By Reference Mode).

Key Options:
  --include          Comma-separated list of TLV tags (Default: hash,ec,x509).
                     Options: hash, ec, x509, data, reference, basereference.
  --keyword          Categorization tag for the audit log (Default: general-event).
  --record-note      A local note for the JSON log (supports @file.txt for content).
  --transaction-note A note embedded in the blockchain transaction (OP_RETURN).
  --mainnet          Mandatory flag to allow transactions on the Mainnet.
  --dry-run          Simulates the TX without making changes.
  --no-broadcast     Updates local stores but does not send to the network.

--------------------------------------------------------------------------------
2. af_sync.py
--------------------------------------------------------------------------------
Synchronizes block headers to your local cache for SPV verification.

Usage:
  python af_sync.py [MODE] [OPTIONS]

Selection Modes:
  --last N           Sync the most recent N blocks.
  --range START-END  Sync a specific height range (e.g., 800000-800100).
  --block H          Sync one specific block height.

Options:
  --network          Override .env setting (main or test).
  --minimal-info     Stores only the absolute minimum data needed for SPV.

--------------------------------------------------------------------------------
3. af_utxo_manager.py
--------------------------------------------------------------------------------
Diagnostic and repair tool for your local wallet state.

Actions:
  stats              Show count and total value of local UTXOs.
  compare            Compare local cache against the blockchain API.
  repair             Smart repair: removes spent and adds confirmed UTXOs.
  full-repair        Wipes local cache and rebuilds it from the blockchain.

--------------------------------------------------------------------------------
4. af_monitor.py
--------------------------------------------------------------------------------
Background process to watch for confirmations and fetch Merkle Proofs (TSC).

Usage:
  python af_monitor.py [--duration MINUTES]

--------------------------------------------------------------------------------
5. Helper Scripts
--------------------------------------------------------------------------------
- control_process.py: Use with "pause", "resume", or "stop" for long batches.
- af_drain_bank.py: Sweeps all funds from the Bank to a target address.
- af_setup_fresh_environment.py: Automated directory and key initialization.