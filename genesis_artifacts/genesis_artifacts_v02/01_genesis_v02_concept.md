**SPV-based Off-Chain Data Verification (AnchorForge v0.2)**

**Overview**
Transactions from and to this address are part of a Proof-of-Concept for preparing off-chain integrity proofs of arbitrary data records (e.g., AI interactions, audit logs, documents, images) using Bitcoin's Simplified Payment Verification (SPV, Bitcoin Whitepaper Sec. 8). A verifier needs only an Integrity Record and a local cache of block headers — no live blockchain access is required.

**Create Integrity Record**
For any data `D` and key pair `I` (with private key `PrK` and public key/certificate `PuK`):
- Hash: Compute `H = Hash(D)` (fingerprint the data).
- Sign: Create `S = Sign(H, PrK)` (prove authorship using ECDSA or X.509).
- Transaction: Build `Tx` with `H`, `S`, `PuK`, embedded in a Safe OP_RETURN (OP_FALSE OP_RETURN) output.
- Broadcast: Send `Tx` to blockchain.
- Merkle Proof: Get `M` (Merkle Proof) for `TxId` after confirmation.
- Store: Save `R = (D, rawTx, TxId, M)` locally as the Integrity Record.

**Verify Integrity Locally**
With `R` and local block headers `BH`, a verifier checks:
- Integrity: Confirm `Hash(R.D)` matches `H` in `R.rawTx` (data is unchanged).
- Authenticity: Verify `S` is valid for `H` using `PuK` or X.509 Certificate (proves authorship).
- Consistency: Ensure `Hash(R.rawTx)` equals `R.TxId` (transaction is authentic).
- Blockchain Inclusion: Confirm `M` proves `R.TxId` is in `BH`’s merkle root (transaction is on-chain).

**PoC:** github.com/40ps/AnchorForge.
**Format:** Safe OP_RETURN uses a TLV (Tag-Length-Value) architecture holding flexible tags: [AppID|Hash|PubKey|Sig|Cert|Data|Ref|Note].

**AnchorForge v0.2: TLV Payload Decoder**

The Integrity Record contains a `raw_tx` hex string. To parse the AnchorForge OP_RETURN payload, look for `OP_FALSE OP_RETURN` followed by these Tag-Length-Value (TLV) blocks. 

**Tags (Hex / ASCII):**
* `f0` (AppID): Identifies the AnchorForge protocol and version.
* `48` ('H'): Hash of the anchored data (Prefix `00` = SHA256).
* `50` ('P'): Public Key for ECDSA (Prefix `00` = Compressed).
* `53` ('S'): ECDSA Signature (Prefix `01` = DER format).
* `43` ('C'): X.509 Certificate (Prefix `01` = PEM format).
* `44` ('D'): Embedded On-Chain Data (Prefix `00` = UTF-8, `01` = RAW).
* `4e` ('N'): Transaction Note (Plain text).
* `58` ('X'): External Reference / URI.

**Parsing Rule:** [Push-Opcode] + [TAG] + [Length-Opcode] + [Prefix-Byte] + [Value]


**Example**
- This transaction is the result of anchoring `D`="AnchorForge v0.2 example data" using the embedded mode.
- The OP_RETURN contains the hash (72 / 0x48), signatures, and public keys/certificates for both ECDSA and X.509.
- Additionally, the `D` is embedded on-chain as `Data` (68 / 0x44).
- You can compare the `Hash` of `D` via sha256sum or online tools.
- This complete text is attached as a `Note` (78 / 0x4E) to demonstrate the TLV flexibility.
- The next transaction to this address will present the Integrity Record `R` to verify this `D` is unchanged using e.g. AnchorForge. It contains: `D`, `TxId`, `rawTx`, `M` (Merkle path after the Tx got confirmed).
- Based on this locally stored information and the blockheader of the confirming block, the information can be fully verified.

- A further transaction will demonstrate anchoring (and embedding small) files by anchoring the Integrity Record to describe this transaction.

((Pitfalls: Hashing text files across different operating systems can alter line endings, and copy-pasting via Ctrl+C/V often introduces hidden characters. Be aware of this when manually verifying hashes!)

**History**
Genesis of v0.1: **5cd8197616fab4a6579ccdd3a782e229c84c0238975aefdb3ea1007a8b1ef6c8** 2025-09-25