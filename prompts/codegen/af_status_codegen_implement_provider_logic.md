Continue from the current af_status skeleton.

Goal:
Incrementally implement the af_status provider logic according to:

- docs/specs/af_status_spec.md
- docs/specs/af_status_architecture.md
- docs/standards/behavioral_invariants.md

Hard constraints:
- Work in small steps.
- Do not implement everything at once.
- Do not modify unrelated files.
- Do not mutate Config globally.
- Do not add remote calls.
- Do not create, repair, truncate, normalize, or save project state.
- Do not print or expose secrets.
- Use .venv/bin/python for all checks.
- Do not use system python or python3.
- Do not install packages.
- Preserve all existing behavior and keep tests passing.

Implementation plan:
Step 1: Implement real overview provider logic.
Step 2: Implement UTXO provider.
Step 3: Implement TX provider.
Step 4: Implement Integrity provider.
Step 5: Implement Headers provider.
Step 6: Implement last queries.
Step 7: Implement info queries.
Step 8: Add focused tests for implemented providers and CLI output.

For each step:
1. State the exact files you plan to modify.
2. Implement only that step.
3. Run:
   .venv/bin/python -m py_compile af_status.py anchorforge/status/*.py anchorforge/status/providers/*.py anchorforge/status/formatters/*.py
   .venv/bin/python -m pytest tests/test_behavioral_invariants.py -q
4. Run any new focused tests for that step.
5. Provide a short review:
   - files changed
   - behavior implemented
   - tests run
   - pass/fail result
   - known limitations
6. Stop and ask for confirmation before starting the next step.

Begin with Step 1 only: real overview provider logic.