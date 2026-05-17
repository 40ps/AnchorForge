"""Human-readable status formatter."""

from __future__ import annotations

from typing import Any

from anchorforge.status.models import StatusResult


def format_text(result: StatusResult) -> str:
    lines: list[str] = []
    command = result.meta.get("command", "status")
    lines.append(f"AnchorForge status: {command}")

    if result.data:
        lines.append("")
        lines.append("Data:")
        for key in sorted(result.data):
            lines.append(f"  {key}: {_format_value(result.data[key])}")

    if result.warnings:
        lines.append("")
        lines.append("Warnings:")
        for warning in result.warnings:
            context = f" ({warning.context})" if warning.context else ""
            lines.append(f"  {warning.level}: {warning.message}{context}")

    return "\n".join(lines)


def _format_value(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{key}={value[key]}" for key in sorted(value))
    if isinstance(value, list):
        return f"{len(value)} item(s)"
    return str(value)
