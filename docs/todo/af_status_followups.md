# af_status Follow-ups

This file tracks known limitations and follow-up work for `af_status.py`.

## Current State

Status: feature complete  
Tag: af-status-v1-feature-complete  
Branch: feature/af-status-cli  
Last feature-complete commit: 6d874f3

Summary:
af_status v1 is implemented, documented, tested with focused status tests,
and guarded by behavioral invariants. Remaining work is tracked as hardening
and follow-up tasks.

## Open

### AFS-001 Publisher test suite failure

Status: Open
Priority: M
Source: Step 8

Description:
Full `pytest` fails during collection in `tests/test_publisher.py`.

Observed error:

```text
ImportError: cannot import name 'Signature' from 'bsv'
```

Notes:

- Focused `af_status` tests pass.
- Behavioral invariant tests pass.
- The failure appears unrelated to `af_status`.

Possible action:

Investigate the installed `bsv` package/API version mismatch and update either
the dependency pin or the publisher tests.

---

### AFS-002 Text formatter consistency

Status: Open
Priority: S

Description:
The JSON contract is stronger than the current text formatter. Text output is
deterministic and compact, but still generic.

Possible action:

Add command-specific text sections for overview, UTXO, TX, integrity, headers,
last, and info while keeping JSON unchanged.

---

### AFS-003 Malformed fixture hardening

Status: Open
Priority: M

Description:
Step 8 added focused status tests for JSON contracts, missing optional files,
network override isolation, and secret redaction. More fixture coverage would
improve confidence around malformed and wrong-type local JSON files.

Possible action:

Add provider-level tests with temporary files for:

- empty files
- malformed JSON
- wrong top-level JSON type
- ambiguous discovered candidates
- mixed valid and invalid records

---

### AFS-004 Config side-effect isolation

Status: Open
Priority: M

Description:
`af_status` avoids additional writes, but current AnchorForge `Config` import
may create configured runtime directories as existing project behavior.

Possible action:

Introduce a side-effect-free configuration snapshot loader for read-only tools,
then remove the documented v1 compatibility exception.

---

### AFS-005 Address-derived path resolution

Status: Open
Priority: M

Description:
Status providers use configured paths plus generic read-only discovery. Future
work should add a public resolver for address-derived wallet paths without
depending on private wallet-manager helpers.

Possible action:

Expose a pure path resolver for wallet address stores and use it in status
context construction when safe public address information is available.

---

### AFS-006 Raw transaction local decoding

Status: Open
Priority: S

Description:
`info tx --rawtx` computes a local txid and reports safe raw hex summary data.
It does not decode transaction inputs/outputs.

Possible action:

If a stable local library API is available, add local-only decoding with safe
summaries and no external lookups.
