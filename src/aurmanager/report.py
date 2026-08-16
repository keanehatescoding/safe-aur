from __future__ import annotations

from .diffscan import DiffResult
from .model import ScanResult, Severity

_COLORS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
_RESET = "\033[0m"


def _render_findings(findings: list, use_color: bool) -> list[str]:
    lines: list[str] = []
    for f in sorted(findings, key=lambda f: f.severity, reverse=True):
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
    return lines


def render_text(result: ScanResult, use_color: bool = True, severity_min: Severity = Severity.INFO) -> str:
    shown = [f for f in result.findings if f.severity >= severity_min]
    if not shown:
        return "CLEAN: no findings" if not result.findings else "CLEAN: no findings at or above the display threshold"

    lines = _render_findings(shown, use_color)
    suffix = f", {len(shown)} shown" if len(shown) != len(result.findings) else ""
    lines.append(
        f"Overall verdict: {result.overall_verdict.name} ({len(result.findings)} finding(s){suffix})"
    )
    return "\n".join(lines)


def render_diff_text(
    diff: DiffResult, use_color: bool = True, severity_min: Severity = Severity.INFO
) -> str:
    new_shown = [f for f in diff.new_findings if f.severity >= severity_min]
    carried_shown = [f for f in diff.carried_findings if f.severity >= severity_min]

    lines: list[str] = []

    lines.append("=== New findings introduced in this update ===")
    if new_shown:
        lines.extend(_render_findings(new_shown, use_color))
    else:
        lines.append("(none)")
        lines.append("")

    if diff.new_functions:
        lines.append(f"New function(s): {', '.join(diff.new_functions)}")
    if diff.new_sources:
        lines.append(f"New source(s): {', '.join(diff.new_sources)}")
    if diff.weakened_checksum_sources:
        lines.append(
            "Checksum coverage weakened for: " + ", ".join(diff.weakened_checksum_sources)
        )
    if diff.new_functions or diff.new_sources or diff.weakened_checksum_sources:
        lines.append("")

    if carried_shown:
        lines.append(
            f"=== Findings unchanged from the previous version ({len(carried_shown)}) ==="
        )
        lines.extend(_render_findings(carried_shown, use_color))

    if diff.resolved_findings:
        lines.append(f"=== Findings resolved in this update ({len(diff.resolved_findings)}) ===")
        for f in diff.resolved_findings:
            lines.append(f"[{f.severity.name}] {f.rule_id} — {f.message}")
        lines.append("")

    lines.append(
        f"Diff verdict: {diff.diff_verdict.name} "
        f"({len(diff.new_findings)} new finding(s), {len(diff.carried_findings)} carried, "
        f"{len(diff.resolved_findings)} resolved)"
    )
    return "\n".join(lines)
