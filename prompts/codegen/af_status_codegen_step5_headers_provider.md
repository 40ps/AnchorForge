Continue with Step 5 only: Headers provider.

Constraints:
- modify only files required for Step 5
- implement local header cache inspection only
- do not implement Last or Info provider logic
- do not introduce remote calls
- do not trigger sync
- do not fetch missing headers
- do not write, save, repair, initialize, normalize, or mutate Config
- do not hardcode local cache filenames or local values
- use .venv/bin/python for all checks

Functional scope:
- inspect local header cache read-only
- tolerate:
  - missing cache
  - empty cache
  - malformed cache
  - wrong-type cache
  - ambiguous cache discovery
- return structured warnings only

Report:
- selected local source path
- cache present: true/false
- cache readable: true/false
- header count
- detected network if available
- readiness state:
    - missing
    - incomplete
    - ready

Readiness rules:
missing:
- no readable header cache

incomplete:
- cache exists but does not cover all locally known confirmed audit records with block references

ready:
- cache exists and covers all locally known confirmed audit records with block references

Rules:
- use local audit records only
- never trigger verification
- never trigger synchronization
- never call BlockHeaderManager.save()
- never call blockchain_service.sync_block_headers()
- never call remote APIs

Checks:
1.
.venv/bin/python -m py_compile \
af_status.py \
anchorforge/status/*.py \
anchorforge/status/providers/*.py \
anchorforge/status/formatters/*.py

2.
.venv/bin/python -m pytest tests/test_behavioral_invariants.py -q

3.
Focused JSON smoke test:

.venv/bin/python af_status.py headers --format json

4.
Optional additional test:

.venv/bin/python af_status.py --format json

Verify:
- valid JSON only
- no sync attempt
- no remote access
- no secret output

At the end:

1. stop automatically
2. summarize files changed
3. summarize implemented behavior
4. list tests/checks run
5. provide git diff summary
6. ask for confirmation before Step 6