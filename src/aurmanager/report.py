from __future__ import annotations

from .model import ScanResult, Severity

_COLORS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
_RESET = "\033[0m"


def render_text(result: ScanResult, use_color: bool = True, severity_min: Severity = Severity.INFO) -> str:
    shown = [f for f in result.findings if f.severity >= severity_min]
    if not shown:
        return "CLEAN: no findings" if not result.findings else "CLEAN: no findings at or above the display threshold"

    lines: list[str] = []
    for f in sorted(shown, key=lambda f: f.severity, reverse=True):
        color = _COLORS.get(f.severity, "") if use_color else ""
        reset = _RESET if use_color else ""
        loc = f"{f.file}:{f.line}" if f.line else str(f.file)
        lines.append(f"{color}[{f.severity.name}]{reset} {f.rule_id} — {loc}")
        lines.append(f"    {f.message}")
        if f.snippet:
            lines.append(f"    | {f.snippet}")
        if f.incident_ref:
            lines.append(f"    Incident: {f.incident_ref}")
        lines.append("")

    suffix = f", {len(shown)} shown" if len(shown) != len(result.findings) else ""
    lines.append(
        f"Overall verdict: {result.overall_verdict.name} ({len(result.findings)} finding(s){suffix})"
    )
    return "\n".join(lines)
