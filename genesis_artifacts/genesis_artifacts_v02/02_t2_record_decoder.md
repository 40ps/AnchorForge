**Inception Record for Genesis Tx1:**
The Integrity Record is proof context for Integrity Record IR-1 of Genesis Transaction 1 (41bd1084bb877acb31df59f76c10adeba98e3c399e6c7a6a48a9f9282786dc33) that has been anchored with `TxId`. IR-1 can also be downloaded from the blockchain using `af_download_file.py` or extracted from the `rawTx` contained in this Integrity Record. Node, a simple copy from the blockchain or from this record may lead to unverifiable data due to OS specific treatment of invisible characters.

**AnchorForge v0.2: TLV Payload Decoder**

This Integrity Record contains a `raw_tx` hex string. To parse the AnchorForge OP_RETURN payload, look for `OP_FALSE OP_RETURN` followed by these Tag-Length-Value (TLV) blocks. 

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