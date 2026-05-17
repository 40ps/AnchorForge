Continue with Step 9 only: documentation and project integration.

Constraints:
- do not introduce new provider functionality
- do not add remote calls
- do not modify business logic unless required for integration
- do not weaken tests or invariants
- use .venv/bin/python for all checks

Goals:

1. Documentation

Create or update:

- CLI documentation
- usage examples
- command overview
- option overview
- JSON output examples
- warning behavior
- local-only/off-chain-first behavior explanation

Suggested locations:

docs/cli/af_status_cli_guide.md
docs/cli/af_status_examples.md

Document:

overview
utxo
tx
integrity
headers
last
info

Include:

- common usage examples
- expected behavior
- examples with missing files
- troubleshooting notes

2. Repository integration

Review:

README.md

If appropriate:

- add af_status mention
- add short usage examples
- add link to CLI guide

3. Follow-up tracking

Create/update:

docs/todo/af_status_followups.md

Record:

- remaining limitations
- known issues
- technical debt
- future ideas

Include:

- publisher test dependency issue
- formatter improvements
- malformed fixture hardening ideas

4. Validation

Run:

.venv/bin/python -m pytest tests/test_behavioral_invariants.py -q

and:

.venv/bin/python af_status.py --help

Do not run unrelated repair work.

At the end:

1. stop automatically
2. summarize files changed
3. summarize documentation added
4. summarize follow-ups recorded
5. provide git diff summary
6. identify recommended next development tasks