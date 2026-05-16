"""Shared status result models."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class StatusWarning:
    level: str
    message: str
    context: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class StatusResult:
    meta: dict[str, Any]
    data: dict[str, Any]
    warnings: list[StatusWarning]

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": self.meta,
            "data": self.data,
            "warnings": [warning.to_dict() for warning in self.warnings],
        }
