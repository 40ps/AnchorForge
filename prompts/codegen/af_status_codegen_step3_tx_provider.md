Continue with Step 3 only: TX provider.

Constraints:
- modify only files required for Step 3
- implement local TX provider logic only
- treat TX store as an independent local documentation source
- read TX stores read-only
- support transaction count, last TXIDs, local TX summaries, and selected source paths
- do not implement Integrity, Headers, Last, or Info provider logic
- do not introduce remote calls
- do not write, save, repair, initialize, or mutate Config
- do not hardcode local cache filenames or local values
- use .venv/bin/python for all checks

At the end:
1. stop automatically
2. summarize files changed
3. summarize implemented behavior
4. list tests/checks run
5. provide git diff summary
6. ask for confirmation before Step 4