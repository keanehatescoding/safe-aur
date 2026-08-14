from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, name: str) -> "Severity":
        return cls[name.upper()]

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    file: Path
    line: int | None = None
    column: int | None = None
    snippet: str | None = None
    incident_ref: str | None = None
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["file"] = str(self.file)
        return d


@dataclass
class RuleContext:
    """Everything a Rule needs to inspect one parsed file (PKGBUILD or .install)."""

    file: Path
    source: str
    ast: Any | None  # bashlex AST root node, or None if parsing failed
    parse_error: str | None = None

    # Structured fields extracted by parser/pkgbuild.py or parser/install_script.py.
    pkgname: str | None = None
    pkgver: str | None = None
    sources: list[str] = field(default_factory=list)
    checksums: dict[str, list[str]] = field(default_factory=dict)  # e.g. {"sha256sums": [...]}

    # function name -> function body AST node (or None if not present)
    functions: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)

    @property
    def overall_verdict(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    def findings_at_or_above(self, threshold: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity >= threshold]

    def to_json(self) -> str:
        return json.dumps(
            {
                "overall_verdict": self.overall_verdict.name,
                "findings": [f.to_dict() for f in self.findings],
            },
            indent=2,
        )
