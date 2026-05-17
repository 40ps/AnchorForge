"""Header cache status provider."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from anchorforge.status.context import StatusContext
from anchorforge.status.models import StatusResult, StatusWarning
from anchorforge.status.readers import read_json_file
from anchorforge.status.resolvers import select_local_json_source


def get_headers_status(context: StatusContext, detail: str) -> StatusResult:
    warnings = list(context.warnings)
    header_path, source_warnings = select_local_json_source(
        "header cache",
        context.header_cache_path,
        context.base_dir,
        (f"cache/**/block_headers_{context.effective_network}.json",),
    )
    warnings.extend(source_warnings)
    audit_path, source_warnings = select_local_json_source(
        "audit log",
        context.audit_log_path,
        context.base_dir,
        (f"output/audit_log_{context.effective_network}.json",),
    )
    warnings.extend(source_warnings)

    headers, header_warnings = _read_optional_dict(header_path, "header cache")
    warnings.extend(header_warnings)
    records, audit_warnings = _read_optional_list(audit_path, "audit log")
    warnings.extend(audit_warnings)

    required_hashes = _confirmed_block_hashes(records)
    available_hashes = _available_block_hashes(headers)
    missing_hashes = sorted(required_hashes - available_hashes)
    cache_present = bool(header_path and header_path.exists())
    cache_readable = isinstance(headers, dict)
    header_count = len(headers) if isinstance(headers, dict) else 0

    return StatusResult(
        meta={"command": "headers"},
        data={
            "detail": detail,
            "paths": {
                "header_cache": _path_to_str(header_path),
                "audit_log": _path_to_str(audit_path),
            },
            "cache_present": cache_present,
            "cache_readable": cache_readable,
            "header_count": header_count,
            "detected_network": _detect_network(headers, header_path),
            "readiness": {
                "state": _readiness_state(cache_readable, missing_hashes),
                "required_block_hash_count": len(required_hashes),
                "covered_block_hash_count": len(required_hashes) - len(missing_hashes),
                "missing_block_hashes": missing_hashes if detail == "full" else missing_hashes[:5],
            },
        },
        warnings=warnings,
    )


def _read_optional_dict(path: Path | None, label: str) -> tuple[dict[str, Any] | None, list[StatusWarning]]:
    if path is None:
        return None, [StatusWarning("WARNING", f"{label} is ambiguous or unavailable", label)]
    data, warnings = read_json_file(path, dict)
    return data if isinstance(data, dict) else None, warnings


def _read_optional_list(path: Path | None, label: str) -> tuple[list[Any] | None, list[StatusWarning]]:
    if path is None:
        return None, [StatusWarning("WARNING", f"{label} is ambiguous or unavailable", label)]
    data, warnings = read_json_file(path, list)
    return data if isinstance(data, list) else None, warnings


def _readiness_state(cache_readable: bool, missing_hashes: list[str]) -> str:
    if not cache_readable:
        return "missing"
    if missing_hashes:
        return "incomplete"
    return "ready"


def _confirmed_block_hashes(records: object) -> set[str]:
    if not isinstance(records, list):
        return set()
    hashes: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        blockchain_record = record.get("blockchain_record")
        if not isinstance(blockchain_record, dict):
            continue
        status = str(blockchain_record.get("status", "")).lower()
        block_hash = blockchain_record.get("block_hash") or blockchain_record.get("blockhash")
        if status == "confirmed" and isinstance(block_hash, str) and block_hash:
            hashes.add(block_hash)
    return hashes


def _available_block_hashes(headers: object) -> set[str]:
    if not isinstance(headers, dict):
        return set()
    hashes: set[str] = set()
    for key, value in headers.items():
        if _looks_like_hash(key):
            hashes.add(key)
        if isinstance(value, dict):
            block_hash = value.get("hash") or value.get("block_hash") or value.get("blockhash")
            if isinstance(block_hash, str) and block_hash:
                hashes.add(block_hash)
    return hashes


def _detect_network(headers: object, path: Path | None) -> str | None:
    if isinstance(headers, dict):
        network = headers.get("network")
        if isinstance(network, str) and network:
            return network
        for value in headers.values():
            if isinstance(value, dict):
                network = value.get("network")
                if isinstance(network, str) and network:
                    return network
    if path:
        name = path.name.lower()
        if "_main" in name:
            return "main"
        if "_test" in name:
            return "test"
    return None


def _looks_like_hash(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _path_to_str(path: Path | None) -> str | None:
    return str(path) if path else None
