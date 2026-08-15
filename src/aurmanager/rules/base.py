from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar, Iterable

from ..model import Finding, RuleContext, Severity


class Rule(ABC):
    rule_id: ClassVar[str]
    category: ClassVar[str]
    default_severity: ClassVar[Severity]
    incident_refs: ClassVar[tuple[str, ...]] = ()

    @abstractmethod
    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        """Inspect ctx and yield any Findings. Must not raise on malformed/unparseable
        input -- rules should degrade gracefully (e.g. skip AST-dependent checks when
        ctx.ast is empty due to a parse error)."""
