# AnchorForge v0.2 Protocol Standard (TLV)

This document defines the formal data structures for the AnchorForge v0.2 protocol. Its purpose is to enable cross-platform compatibility for any tool interacting with AnchorForge audit records.

---

## 1. Transaction Layer

### Output Script
AnchorForge records are stored in the `scriptPubKey` of a Bitcoin SV transaction output.
- **Type:** `OP_FALSE OP_RETURN` (also known as "Safe OP_RETURN").
- **Prefix:** `0x006a`
- **Data Pushes:** All protocol elements are pushed as individual data chunks following the prefix.

---

## 2. Atomic Tag (TLV) Format

Version 0.2 utilizes a Tag-Length-Value (TLV) inspired structure. Each data element is self-describing.

### Element Structure
| Byte | Field | Description |
| :--- | :--- | :--- |
| 0 | **Tag** | A single character (1 byte) identifying the data type. |
| 1 | **Format/Algo** | A 1-byte identifier for the sub-type (e.g., Hash algorithm or Signature format). |
| 2..n | **Value** | The actual payload (hash bytes, signature bytes, etc.). |

---

## 3. Defined Tags & Sub-types

Based on `core_defs.py`, the following tags are recognized:

### Tag 'H' (Hash)
- **Format Byte `0x00`:** SHA-256 (32 bytes).
- **Purpose:** The core commitment to the off-chain data.

### Tag 'S' (EC Signature)
- **Format Byte `0x00`:** RAW (r + s, 64 bytes).
- **Format Byte `0x01`:** DER Encoded (variable length).
- **Format Byte `0x02`:** BSM (Bitcoin Signed Message).

### Tag 'P' (Public Key)
- **Format Byte `0x00`:** Compressed (33 bytes).
- **Format Byte `0x01`:** Uncompressed (65 bytes).

### Tag 'C' (X.509 Certificate)
- **Format Byte `0x00`:** PEM format (Text).

### Tag 'X' (X.509 Signature)
- **Format Byte `0x01`:** RSA PKCS1v15 with SHA-256.

### Tag 'D' (On-Chain Data)
- **Format Byte `0x00`:** UTF-8 String.
- **Format Byte `0x01`:** Raw Binary Data.

### Tag 'R' (Reference)
- **Format Byte `0x00`:** Full absolute file path.
- **Format Byte `0x01`:** Base filename only.

---

## 4. Ordering Rules

While TLV allows for flexible ordering, AnchorForge v0.2 follows these conventions:
1. **Protocol ID:** The first push should be `0xF0` followed by the version string (e.g., "AnchorForge v0.2").
2. **Primary Hash:** The Hash (`H`) should appear before any associated signatures (`S` or `X`).
3. **Contextual Data:** Notes (`N`) and References (`R`) can be appended at the end of the script.
