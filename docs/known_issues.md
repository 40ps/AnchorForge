Known Issues & Roadmap (v0.2-beta)

While AnchorForge v0.2 introduces the new TLV-standard and X.509 support, 
there are several areas that are still under development.

## Issues
- using os.makedirs(d, exists_ok=True) in config.py will cause creation of directories even if only unit tests are wanted 

## ⚠️ Current Limitations (Work in Progress)
- **Error Handling:** Some cases in network timeouts (WhatsOnChain API) are not gracefully handled yet.
- **UTXO Management:** The current UTXO-let logic is optimized for sequential batching; high-parallelism might lead to collisions.
- **SPV Validation:** The full Merkle-path validation is implemented but needs more stress-testing with deep block re-org scenarios.

## 🚀 Roadmap to v0.3
- [ ] Implement automated re-try logic for API calls.
- [ ] Add a graphical dashboard for the Audit-Logs.
- [ ] Full integration of the BRC-72 (or similar) token standard for asset-linked anchors.

*Your feedback and bug reports are highly appreciated!*