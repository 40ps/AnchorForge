# Project History
## 0. Origin
June 10th, by working title *Trust and Integrity for AI*, the original concept was submitted (by Wolfgang Lohmann) during a global genAI hackathon organized by Randstad Digital, using earlier ideas (see (ACKKNOWLEDGEMENTS.md)).


## 1. The Vision
AnchorForge began as a technical demonstration to show that it 
* is easy to use a public blockchain (Bitcoin SV) for timestamping
* it can provide scalable, immutable timestamps
* prooves can be nearly self-contained for off-chain data verification, making it scalable for huge number of verifications.
Meanwhile, the vision has become to make this Proof-of-Concept usable and safe enough that even as a demonstration tool, it can provide usefulness to timestamp data, files.

## 2. Milestones

### Version 0.1 (Legacy)
- Initial Proof of Concept
- Working name VAI: Verification of AI Integrity
- Rigid positional data format in OP_RETURN.
- Basic support for SHA-256 hashing and ECDSA signatures.
- Local UTXO caching introduced to manage "Self-Spending" transactions.

### Version 0.2 (Current - TLV Protocol)
- **Flexible Architecture:** Implementation of the Atomic Tag (TLV - Tag-Length-Value) format.
- **Multi-Signature Support:** Added support for combining ECDSA and X.509 (RSA) signatures in a single anchor.
- **Enhanced Verification:** Refactored the 'verifier.py' to ensure mandatory hash checks and modular payload validation.
- **Environment Automation:** Introduction of 'af_setup_fresh_environment.py' to streamline deployment on new machines.
- **Public access:** Cleaned up much ad-hoc code, refactored, made it more generic, allowed files to be timestamped, openend up github

## 3. Acknowledgements
see (ACKNOWLEDGEMENTS.md) for actual acknowledgements. As this is the first public accessible version, ACK v0.2 is the first written ACK. History acknowledgements will be in subdirectory (doc/history/acknkowledgements/)

## 4. Future Features
This is a tiny side project that I want to use for presentations. However, it grew, and maybe some features are worth to be introduced. Among the things approached may be
- tests (yes, yes)
- RFC-Standard (RFC 8785: JSON Canonicalization Scheme - JCS) How to sort and format before hashing JSON (super Feature for v0.3?)
- Single Audit Record creation
- separation of logs
- separation of env-IO
- Verbose mode vs pure mode (smallest data possible for comparison)
- Increased Usability
- More safe creation of new environments/wallet filling/configuring
- BRC-100 format
- secured wallets (password/encrypted)
- using BSV best practices, using existing wallet tools
- Integration of a dedicated 'Library' mode to use AnchorForge as a dependency in other Python projects.
- Implementation of a GUI for the 'verifier' to make audit trails accessible to non-technical users.
- Support for complex Merkle Tree batching to anchor thousands of files in a single transaction.
- replacement of JSON database /alternative data base
- *Support for tax reporting (CSV for spends)*
- more to come
