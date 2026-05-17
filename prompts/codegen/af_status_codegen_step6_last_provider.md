Continue with Step 6 only: Last provider.

Constraints:
- modify only files required for Step 6
- implement local last-query aggregation only
- reuse existing provider logic where possible
- do not duplicate UTXO, TX, Integrity, or Headers logic
- do not implement Info provider logic
- do not introduce remote calls
- do not write, save, repair, initialize, normalize, or mutate Config
- do not hardcode local cache filenames or local values
- use .venv/bin/python for all checks

Functional scope:

Implement:

af_status.py last <type> [n]

Supported types:

- txid
- tx
- ir
- utxo-created
- utxo-used
- warnings

Rules:

- default n = 5
- max n = 100
- newest first
- invalid n returns CLI error with structured help
- unknown type returns CLI error

Behavior:

last txid:
- return newest TXIDs from local TX provider

last tx:
- return newest local TX summaries

last ir:
- return newest integrity records

last utxo-created:
- return newest created UTXOs

last utxo-used:
- return newest used UTXOs

last warnings:
- return newest warnings collected from context/providers if available

Rules:

- use already implemented provider results
- do not re-read files directly if provider data already exists
- tolerate missing data with warnings
- preserve deterministic ordering
- JSON output must remain pure JSON

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
Focused smoke tests:

.venv/bin/python af_status.py last txid
.venv/bin/python af_status.py last ir
.venv/bin/python af_status.py last utxo-created --format json

4.
Optional:

.venv/bin/python af_status.py --format json

Verify:

- valid JSON only
- deterministic ordering
- no remote access
- no secret output

At the end:

1. stop automatically
2. summarize files changed
3. summarize implemented behavior
4. list tests/checks run
5. provide git diff summary
6. ask for confirmation before Step 7