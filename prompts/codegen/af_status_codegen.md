# Code Generation Prompt: AnchorForge `af_status.py`

You are a senior software engineer with expertise in Python, CLI design, software architecture, Bitcoin/BSV, SPV verification, local state inspection, and maintainable open-source development.

The specification is located at:
docs/specs/af_status_spec.md

## Repository Context

Target repository:

```text
https://github.com/40ps/AnchorForge
```

AnchorForge is a Python proof-of-concept for anchoring data integrity records on BitcoinSV and verifying them off-chain using SPV-style local data.

Before writing code, inspect the repository structure and existing modules. Reuse existing project functionality wherever possible.

Relevant existing areas likely include:

* configuration handling
* UTXO management
* transaction storage
* audit / integrity logs
* header cache / SPV sync
* existing CLI tools

Do not invent file names or internal APIs without first checking the current implementation.

## Primary Task

Implement a new CLI tool:

```text
af_status.py
```

The tool must provide a read-only status, information, and inspection interface for the local AnchorForge state.

Use the specification in:

```text
docs/af_status_spec.md
```

as the primary source of requirements.

If the specification conflicts with current repository code, prefer compatibility with the current codebase, but document any assumption or limitation clearly.

## Language Rules

* Conversation and explanations may be in German.
* Code, comments, CLI help text, variable names, function names, output labels, documentation strings, and test names must be in English.

## Core Design Requirements

Implement the tool as a thin CLI frontend.

Business logic must be placed in reusable library modules, not hardcoded inside the CLI script.

Preferred structure:

```text
anchorforge/
  status/
    __init__.py
    context.py
    resolvers.py
    providers/
      network.py
      utxo.py
      tx.py
      integrity.py
      headers.py
      warnings.py
    formatters/
      text.py
      json.py

af_status.py
```

Adapt this structure to the actual repository layout if needed.

## Required CLI Behavior

Support these commands:

```bash
af_status.py
af_status.py overview
af_status.py utxo
af_status.py tx
af_status.py integrity
af_status.py headers
af_status.py warnings
af_status.py last <type> [n]
af_status.py info <type> ...
```

Supported `last` types:

```text
txid
tx
ir
utxo-created
utxo-used
warnings
```

Supported `info` types:

```bash
af_status.py info tx --txid <txid>
af_status.py info tx --rawtx <rawtx>
af_status.py info ir --id <log_id>
af_status.py info ir --keyword <keyword>
af_status.py info ir --txid <txid>
af_status.py info ir --date-from <date>
af_status.py info ir --date-to <date>
af_status.py info utxo --outpoint <txid:vout>
```

Global options:

```bash
--network main|test
--format text|json
--detail basic|normal|full
-v / -vv
--no-color
```

Default behavior:

```bash
af_status.py
```

must behave like:

```bash
af_status.py overview
```

## Functional Requirements

The default overview must show:

* tool version
* AnchorForge library version
* config network
* CLI override network
* effective network
* config source path
* bank address
* working / UTXO address
* UTXO summary:

  * count
  * total satoshis
  * min/max
  * dust count
* last local TXID
* integrity summary:

  * record count
  * last log_id
  * timestamp
  * keyword if available
* header readiness:

  * ready / incomplete / missing
* critical warnings
* help hint

## Data Source Rules

Use local sources first.

Source priority:

1. CLI override
2. `.env` / project config
3. data files only for validation and consistency checks

Primary local sources:

* config / `.env`
* UTXO store
* TX store
* audit / integrity logs
* header cache

The TX store must be treated as an independent documentation source for transactions, not merely as a supplement to audit logs.

Remote access must not happen unless explicitly requested. If remote comparison is not implemented in this iteration, leave a clean extension point.

## Security Requirements

Never output:

* private keys
* WIFs
* seed phrases
* secret config values
* API keys

This applies to both text and JSON output.

If key material exists, only report safe derived/public information such as addresses or presence flags.

## Output Requirements

Default format: human-readable text.

Also support:

```bash
--format json
```

JSON output must use a stable top-level structure:

```json
{
  "meta": {},
  "data": {},
  "warnings": []
}
```

Warnings must follow a consistent structure:

```json
{
  "level": "INFO|WARNING|CRITICAL|ERROR",
  "message": "...",
  "context": "..."
}
```

Do not mix human text into JSON output.

## Error Handling

Use these exit codes:

```text
0 success
1 runtime error
2 CLI misuse
3 configuration failure
```

Follow this principle:

> Fail soft, not silent.

The tool should report as much useful information as possible, even when some sources are missing or incomplete.

## Architecture Requirements

Implement:

* central status context
* central path resolvers
* provider functions per domain
* separate text and JSON formatters

Do not scatter hardcoded paths throughout the code.

All path resolution should be centralized to support future migration to separate `main/` and `test/` data directories.

## Wallet Abstraction Requirement

Do not hardwire the implementation to direct WIF/private-key handling.

Prepare the design for future wallet abstraction, including possible BRC-100 wallet support.

The CLI contract should not depend on the current secret storage model.

## Testing

Add tests where feasible.

At minimum, structure the code so provider logic can be tested independently from CLI parsing.

Prefer pure functions and mockable file-system access.

## Deliverables

Produce:

1. New `af_status.py`
2. New reusable library modules as needed
3. Any minimal tests that fit the current test setup
4. Updated documentation if straightforward
5. A concise implementation note explaining:

   * what was implemented
   * assumptions made
   * limitations
   * follow-up tasks

## Important Constraints

* Read-only only
* No repair behavior
* No transaction creation
* No signing
* No automatic remote calls
* No secrets in output
* Reuse existing code where possible
* Keep implementation maintainable and modular

## Expected Result

The result should be a functional first implementation of `af_status.py` that follows the specification, integrates with the current AnchorForge codebase, and provides a stable foundation for future CLI tools, documentation, diagnostics, and UI integration.
