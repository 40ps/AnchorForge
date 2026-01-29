# Architecture & Protocol Specification

This document provides a deep dive into the technical design of AnchorForge v0.2, covering the high-level architecture, the Atomic Tag (TLV) protocol, and the off-chain verification logic.

---

## 1. High-Level Design: The "Self-Spend" Concept

AnchorForge is designed for high-frequency, low-cost data anchoring. Instead of relying on a third-party service, the user acts as their own "bank" and "auditor".

### Core Principle
- **Self-Spending:** Every audit record is a transaction sent to the user's own address.
- **Privacy by Default:** Data can be stored off-chain while only a cryptographic commitment (hash) is anchored on the public ledger.
- **Independence:** Verification does not require a full node or specialized API permissions, relying instead on Simplified Payment Verification (SPV).

---

## 2. Protocol v0.2: Atomic Tags (TLV)

The protocol utilizes a Tag-Length-Value (TLV) structure within the `OP_RETURN` output of a transaction. This modular format allows for flexible combinations of data, signatures, and references.

### TLV Structure
Each element in the payload consists of:
1. **Tag:** A 1-byte identifier.
2. **Value:** The data payload associated with the tag.

### Supported Tags (v0.2)

| Tag | Hex / Char | Name | Description |
| :--- | :--- | :--- | :--- |
| `H` | `0x48` | **Hash** | SHA-256 hash of the anchored data. Preceded by a 1-byte algorithm ID (`0x00`). |
| `S` | `0x53` | **EC Signature** | ECDSA signature. Preceded by a 1-byte format ID (e.g., `0x01` for DER). |
| `P` | `0x50` | **Public Key** | The public key used for the ECDSA signature. Preceded by a key type ID. |
| `C` | `0x43` | **X.509 Certificate** | Full PEM-encoded certificate for identity verification. |
| `X` | `0x58` | **X.509 Signature** | RSA signature created with the private key corresponding to the certificate. |
| `D` | `0x44` | **Data** | Optional raw data embedded directly on-chain. |
| `R` | `0x52` | **Reference** | A file path or filename reference for off-chain assets. |
| `N` | `0x4E` | **Note** | Human-readable UTF-8 string/comment. |

---

## 3. Verification Workflow

The verification process is handled by `verifier.py` and follows a tiered approach to ensure absolute data integrity.

### Step 1: Content Integrity
The verifier first ensures that the local data (either an embedded string or an external file) has not been tampered with:
- **Embedded Mode:** The string in the local log is re-hashed.
- **By-Reference Mode:** The file pointed to by the audit record is located and hashed.
- The resulting hash MUST match the `Tag 'H'` value extracted from the blockchain transaction.

### Step 2: Authorship Proof (Signatures)
- **ECDSA:** The verifier extracts the public key (`Tag 'P'`) and verifies the signature (`Tag 'S'`) against the hash.
- **X.509:** The verifier parses the certificate (`Tag 'C'`), extracts the RSA public key, and verifies the identity and signature (`Tag 'X'`).

### Step 3: Blockchain Inclusion (SPV)
This is the "Zero-Trust" component. Instead of asking a server "is this TX valid?", the verifier proves it mathematically:
1. **Merkle Path:** The verifier uses a Merkle Path (fetched by the `af_monitor.py`) to link the Transaction ID to a specific Merkle Root.
2. **Block Header:** The Merkle Root is verified against a local cache of 80-byte block headers (synced via `af_sync.py`).
3. **Chain Validity:** The block header is verified to be part of the longest proof-of-work chain.

---

## 4. Scalability & Efficiency

AnchorForge solves the scalability bottleneck of traditional auditing:
- **Off-Chain Verification:** Since the verification logic is purely mathematical and runs on the client-side, it scales linearly with the number of auditors without taxing the blockchain or a central server.
- **Minimal Storage:** A verifier only needs the ~300-byte audit record and a header cache (approx. 4MB per year of blockchain history).
- **Self-Cleaning Wallet:** The "Self-Spend" mechanism allows the user to reuse their funds continuously, requiring only a tiny fraction of BSV for perpetual logging.
