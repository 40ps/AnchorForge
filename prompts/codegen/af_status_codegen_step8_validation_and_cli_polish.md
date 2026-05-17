Continue with Step 7 only: Info provider.

Constraints:
- modify only files required for Step 7
- implement local object inspection only
- reuse existing provider logic where possible
- do not duplicate TX, Integrity, UTXO, or Headers logic
- do not introduce remote calls
- do not write, save, repair, initialize, normalize, or mutate Config
- do not hardcode local cache filenames or local values
- use .venv/bin/python for all checks

Functional scope:

Implement:

af_status.py info <type> ...

Supported:

info tx --txid <txid>
info tx --rawtx <rawtx>

info ir --id <log_id>
info ir --keyword <keyword>
info ir --txid <txid>
info ir --date-from <date>
info ir --date-to <date>

info utxo --outpoint <txid:vout>

Rules:

TX:
- inspect local TX data only
- no network lookup
- for --rawtx:
  - compute txid if existing library support exists
  - otherwise return local summary only
- do not decode using external services

Integrity:
- reuse integrity provider filtering logic
- keyword matching:
  case-insensitive substring

UTXO:
- search local UTXOs by exact outpoint match

General:

- object not found → structured warning
- malformed query → CLI error
- preserve deterministic output
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

.venv/bin/python af_status.py info tx --txid example
.venv/bin/python af_status.py info ir --keyword anchor
.venv/bin/python af_status.py info utxo --outpoint deadbeef:0 --format json

4.
Optional:

.venv/bin/python af_status.py --format json

Verify:

- valid JSON only
- no remote access
- no secret output
- object not found handled via warnings

At the end:

1. stop automatically
2. summarize files changed
3. summarize implemented behavior
4. list tests/checks run
5. provide git diff summary
6. ask for confirmation before Step 8