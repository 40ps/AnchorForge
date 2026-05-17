Continue with Step 4 only: Integrity provider.

Constraints:
- modify only files required for Step 4
- implement local Integrity/Audit Log provider logic only
- read audit/integrity logs read-only
- do not implement Headers, Last, or Info provider logic
- do not introduce remote calls
- do not write, save, repair, initialize, normalize, or mutate Config
- do not hardcode local cache filenames or local values
- use .venv/bin/python for all checks

Functional scope:
- read the selected/default audit log source
- tolerate missing, empty, malformed, wrong-type, and ambiguous audit logs with structured warnings
- report selected local source path
- report record count
- report last records
- report last log_id if available
- report last timestamp if available
- report last keyword if available
- report last txid if available
- support filtering by:
  - --keyword
  - --txid
  - --date-from
  - --date-to
- keyword matching default: case-insensitive substring match
- date filtering should be best-effort and warning-based if timestamps cannot be parsed

Output expectations:
- text output remains deterministic and compact
- JSON output remains pure JSON
- no secrets in output

Checks:
1. Run:
   .venv/bin/python -m py_compile af_status.py anchorforge/status/*.py anchorforge/status/providers/*.py anchorforge/status/formatters/*.py
2. Run:
   .venv/bin/python -m pytest tests/test_behavioral_invariants.py -q
3. Run a focused Integrity JSON smoke check, for example:
   .venv/bin/python af_status.py integrity --format json

At the end:
1. stop automatically
2. summarize files changed
3. summarize implemented behavior
4. list tests/checks run
5. provide git diff summary
6. ask for confirmation before Step 5