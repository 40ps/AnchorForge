"""Read-only status CLI for local AnchorForge state."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from anchorforge.status.context import ConfigLoadError, build_status_context
from anchorforge.status.formatters.json import format_json
from anchorforge.status.formatters.text import format_text
from anchorforge.status.providers.headers import get_headers_status
from anchorforge.status.providers.info import get_info_status
from anchorforge.status.providers.integrity import get_integrity_status
from anchorforge.status.providers.last import get_last_status
from anchorforge.status.providers.overview import get_overview_status
from anchorforge.status.providers.tx import get_tx_status
from anchorforge.status.providers.utxo import get_utxo_status
from anchorforge.status.providers.warnings import get_warnings_status


EXIT_SUCCESS = 0
EXIT_RUNTIME_ERROR = 1
EXIT_CLI_MISUSE = 2
EXIT_CONFIG_FAILURE = 3


def _build_parser() -> argparse.ArgumentParser:
    subcommand_globals = argparse.ArgumentParser(add_help=False)
    _add_global_options(subcommand_globals, suppress_defaults=True)

    parser = argparse.ArgumentParser(
        prog="af_status.py",
        description="Inspect local AnchorForge status without modifying state.",
    )
    _add_global_options(parser, suppress_defaults=False)

    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("overview", parents=[subcommand_globals])
    subparsers.add_parser("utxo", parents=[subcommand_globals])
    subparsers.add_parser("tx", parents=[subcommand_globals])
    subparsers.add_parser("integrity", parents=[subcommand_globals])
    subparsers.add_parser("headers", parents=[subcommand_globals])
    subparsers.add_parser("warnings", parents=[subcommand_globals])

    last_parser = subparsers.add_parser("last", parents=[subcommand_globals])
    last_parser.add_argument(
        "type",
        choices=("txid", "tx", "ir", "utxo-created", "utxo-used", "warnings"),
    )
    last_parser.add_argument("n", nargs="?", type=int, default=5)

    info_parser = subparsers.add_parser("info", parents=[subcommand_globals])
    info_parser.add_argument("type", choices=("tx", "ir", "utxo"))
    info_parser.add_argument("--txid")
    info_parser.add_argument("--rawtx")
    info_parser.add_argument("--id")
    info_parser.add_argument("--keyword")
    info_parser.add_argument("--date-from")
    info_parser.add_argument("--date-to")
    info_parser.add_argument("--outpoint")

    return parser


def _add_global_options(parser: argparse.ArgumentParser, suppress_defaults: bool) -> None:
    default = argparse.SUPPRESS if suppress_defaults else None
    parser.add_argument("--network", choices=("main", "test"), default=default)
    parser.add_argument("--format", choices=("text", "json"), default=argparse.SUPPRESS if suppress_defaults else "text")
    parser.add_argument(
        "--detail",
        choices=("basic", "normal", "full"),
        default=default,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=argparse.SUPPRESS if suppress_defaults else 0,
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=argparse.SUPPRESS if suppress_defaults else False,
    )


def _resolve_detail(args: argparse.Namespace) -> str:
    if args.detail:
        return args.detail
    if args.verbose:
        return "full"
    return "normal"


def _dispatch(args: argparse.Namespace):
    detail = _resolve_detail(args)
    context = build_status_context(args.network)
    command = args.command or "overview"

    if command == "overview":
        return get_overview_status(context, detail)
    if command == "utxo":
        return get_utxo_status(context, detail)
    if command == "tx":
        return get_tx_status(context, detail)
    if command == "integrity":
        return get_integrity_status(context, detail)
    if command == "headers":
        return get_headers_status(context, detail)
    if command == "warnings":
        return get_warnings_status(context, detail)
    if command == "last":
        return get_last_status(context, detail, args.type, args.n)
    if command == "info":
        return get_info_status(context, detail, vars(args))
    raise RuntimeError(f"Unsupported command: {command}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else EXIT_CLI_MISUSE

    try:
        result = _dispatch(args)
    except ConfigLoadError as exc:
        if args.format == "json":
            print(format_json(exc.to_result()))
        else:
            print(format_text(exc.to_result()))
        return EXIT_CONFIG_FAILURE
    except Exception as exc:
        if args.format == "json":
            from anchorforge.status.models import StatusResult, StatusWarning

            result = StatusResult(
                meta={"command": args.command or "overview"},
                data={},
                warnings=[StatusWarning("ERROR", str(exc), "runtime")],
            )
            print(format_json(result))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    if args.format == "json":
        print(format_json(result))
    else:
        print(format_text(result))
    return EXIT_SUCCESS


def main_entry() -> int:
    return main()


if __name__ == "__main__":
    raise SystemExit(main())
