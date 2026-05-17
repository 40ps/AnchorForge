Resume implementation and continue following the incremental plan.

Remain on Step 1 only: Overview provider.

Constraints:
- modify only files required for Step 1
- do not start UTXO, TX, Integrity, Headers, Last, or Info provider implementation
- do not introduce remote calls
- do not introduce writes or repairs
- do not mutate Config
- do not hardcode local cache filenames or local values

At the end:
1. stop automatically
2. summarize files changed
3. summarize implemented behavior
4. list tests/checks run
5. provide git diff summary
6. ask for confirmation before Step 2