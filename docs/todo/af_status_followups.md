# af_status Follow-ups

## Open

### AFS-001 Publisher test suite failure
Status: Open
Priority: M
Source: Step 8

Description:
Full pytest fails during collection in tests/test_publisher.py.

Error:
bsv.Signature unavailable from installed package.

Notes:
Focused af_status tests pass.
Appears unrelated to af_status.

Possible action:
Investigate bsv package/API version mismatch.

---

### AFS-002 Text formatter consistency

Status: Open
Priority: S

Description:
JSON contract currently stronger than text presentation.

Future:
Improve section formatting and readability.

---