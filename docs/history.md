# Project History & Acknowledgements

## 1. The Vision
AnchorForge began as a technical demonstration to show how a public blockchain (Bitcoin SV) can provide scalable, immutable timestamps for off-chain data. The goal was to create a toolset that allows developers to anchor information without the overhead of maintaining a full node or paying high transaction fees.

## 2. Milestones

### Version 0.1 (Legacy)
- Initial Proof of Concept.
- Rigid positional data format in OP_RETURN.
- Basic support for SHA-256 hashing and ECDSA signatures.
- Local UTXO caching introduced to manage "Self-Spending" transactions.

### Version 0.2 (Current - TLV Protocol)
- **Flexible Architecture:** Implementation of the Atomic Tag (TLV - Tag-Length-Value) format.
- **Multi-Signature Support:** Added support for combining ECDSA and X.509 (RSA) signatures in a single anchor.
- **Enhanced Verification:** Refactored the 'verifier.py' to ensure mandatory hash checks and modular payload validation.
- **Environment Automation:** Introduction of 'af_setup_fresh_environment.py' to streamline deployment on new machines.

## 3. Acknowledgements
This project relies on the excellent work of the Bitcoin SV developer community. Special thanks to:
- **bsv-sdk (Python):** The core library used for transaction building and cryptographic operations.
- **WhatsOnChain:** For providing the robust API infrastructure used for blockchain inquiries and broadcasting.
- **The Python Cryptography Authority (PyCA):** For the underlying libraries used in X.509 certificate handling.

## 4. Future Roadmap
- Integration of a dedicated 'Library' mode to use AnchorForge as a dependency in other Python projects.
- Implementation of a GUI for the 'verifier' to make audit trails accessible to non-technical users.
- Support for complex Merkle Tree batching to anchor thousands of files in a single transaction.
