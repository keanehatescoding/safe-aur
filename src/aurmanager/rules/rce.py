from __future__ import annotations

from typing import Iterable

from ..model import Finding, RuleContext, Severity
from ..parser.bash_ast import (
    DOWNLOADERS,
    command_name,
    command_words,
    describe_scope,
    download_output_targets,
    iter_scopes,
    line_of,
    normalize_path,
    walk,
)
from .base import Rule

_DOWNLOADERS = DOWNLOADERS
_INTERPRETERS = {"bash", "sh", "zsh", "dash", "python", "python3", "perl", "source", "."}
_PATCH_LIKE = (".patch", ".diff")
_normalize_path = normalize_path
_download_output_targets = download_output_targets


def _finding_at(rule: Rule, ctx: RuleContext, offset: int, message: str, remediation: str) -> Finding:
    line = line_of(offset, ctx.source)
    snippet = ctx.source.splitlines()[line - 1].strip() if line else None
    return Finding(
        rule_id=rule.rule_id,
        severity=rule.default_severity,
        message=message,
        file=ctx.file,
        line=line,
        snippet=snippet,
        incident_ref=rule.incident_refs[0] if rule.incident_refs else None,
        remediation=remediation,
    )


class RCE001CurlPipeBash(Rule):
    """Piping curl/wget output directly into a shell/interpreter executes remote
    content sight-unseen at build or install time -- the exact mechanism used in the
    2018 acroread AUR package hijack, where a curl-piped install payload added
    persistence and exfiltrated system info. See tests/fixtures/incidents/
    2018_acroread_curl_pipe_bash/SOURCE.md."""

    rule_id = "RCE001"
    category = "rce"
    default_severity = Severity.CRITICAL
    incident_refs = ("AUR-2018-acroread",)

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        findings: list[Finding] = []
        for fn_name, fn_node in iter_scopes(ctx):
            for node in walk(fn_node):
                if getattr(node, "kind", None) != "pipeline":
                    continue
                commands = [p for p in node.parts if getattr(p, "kind", None) == "command"]
                if len(commands) < 2:
                    continue
                first_name = command_name(commands[0])
                last_name = command_name(commands[-1])
                if first_name in _DOWNLOADERS and last_name in _INTERPRETERS:
                    findings.append(
                        _finding_at(
                            self,
                            ctx,
                            node.pos[0],
                            message=(
                                f"{describe_scope(fn_name)} pipes the output of '{first_name}' "
                                f"directly into '{last_name}', executing remote content without "
                                f"any integrity check or human review."
                            ),
                            remediation=(
                                "Never pipe curl/wget output directly into a shell. Download "
                                "to a file, verify its checksum/signature, and review its "
                                "contents before executing anything."
                            ),
                        )
                    )
        return findings


class RCE002ProcessSubstitutionSource(Rule):
    """`source <(curl ...)` / `. <(wget ...)` is functionally identical to piping curl
    into bash -- process substitution just hides it from a casual `grep -r curl.*bash`
    review."""

    rule_id = "RCE002"
    category = "rce"
    default_severity = Severity.CRITICAL
    incident_refs = ("AUR-2018-acroread",)

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        findings: list[Finding] = []
        for fn_name, fn_node in iter_scopes(ctx):
            for node in walk(fn_node):
                if getattr(node, "kind", None) != "command":
                    continue
                if command_name(node) not in ("source", "."):
                    continue
                for part in getattr(node, "parts", []):
                    for sub in walk(part):
                        if getattr(sub, "kind", None) != "processsubstitution":
                            continue
                        inner = sub.command
                        if getattr(inner, "kind", None) == "command" and command_name(inner) in _DOWNLOADERS:
                            findings.append(
                                _finding_at(
                                    self,
                                    ctx,
                                    node.pos[0],
                                    message=(
                                        f"{describe_scope(fn_name)} sources a process "
                                        f"substitution that runs '{command_name(inner)}', "
                                        f"executing fetched content without any integrity check."
                                    ),
                                    remediation=(
                                        "Download to a file, verify it, and review its contents "
                                        "before sourcing or executing it."
                                    ),
                                )
                            )
        return findings


class RCE003FetchThenExecute(Rule):
    """A less obvious variant of the same technique: download to a temp file, mark it
    executable, then run it -- instead of a direct pipe. Same effect (remote code runs
    unreviewed), just spread across a couple of statements."""

    rule_id = "RCE003"
    category = "rce"
    default_severity = Severity.HIGH

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        findings: list[Finding] = []
        for fn_name, fn_node in iter_scopes(ctx):
            downloaded_paths: dict[str, int] = {}
            commands: list = []
            for node in walk(fn_node):
                if getattr(node, "kind", None) == "command":
                    commands.append(node)

            for cmd in commands:
                words = command_words(cmd)
                if not words or words[0] not in _DOWNLOADERS:
                    continue
                for target in _download_output_targets(words):
                    downloaded_paths[_normalize_path(target)] = cmd.pos[0]

            if not downloaded_paths:
                continue

            for cmd in commands:
                words = command_words(cmd)
                if not words:
                    continue
                # Only flag actual execution of the downloaded file, not the
                # chmod +x step alone -- otherwise a single download-then-run chain
                # produces two redundant findings for the same underlying issue.
                target = None
                if _normalize_path(words[0]) in downloaded_paths:
                    target = _normalize_path(words[0])
                elif len(words) >= 2 and words[0] in _INTERPRETERS and _normalize_path(words[1]) in downloaded_paths:
                    target = _normalize_path(words[1])

                if target in downloaded_paths:
                    findings.append(
                        _finding_at(
                            self,
                            ctx,
                            cmd.pos[0],
                            message=(
                                f"{describe_scope(fn_name)} downloads a file to '{target}' and "
                                f"then executes it, running fetched content without any "
                                f"integrity check or human review."
                            ),
                            remediation=(
                                "Verify the checksum/signature of downloaded files and review "
                                "their contents before executing them."
                            ),
                        )
                    )
        return findings


class RCE004DisguisedSourceExecuted(Rule):
    """A `source=()` entry named to look like an inert patch/data file, but that is
    actually sourced or directly executed by a build-lifecycle function -- the
    disguise used in the 2025 librewolf-fix-bin/firefox-patch-bin Chaos RAT packages,
    where a 'patches' source entry pointed at an attacker-controlled repo and was
    executed at build time instead of applied with `patch`. See
    tests/fixtures/incidents/2025_chaos_rat_disguised_source/SOURCE.md."""

    rule_id = "RCE004"
    category = "rce"
    default_severity = Severity.HIGH
    incident_refs = ("AUR-2025-chaos-rat",)

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        findings: list[Finding] = []
        patch_like_names = set()
        for src in ctx.sources:
            # makepkg's `alias::url` form saves the file locally as `alias`,
            # regardless of the URL -- that's the name referenced elsewhere in the
            # PKGBUILD, so it's what we need to check/collect.
            if "::" in src:
                local_name = src.split("::", 1)[0]
            else:
                local_name = src.rsplit("/", 1)[-1]
            if any(local_name.lower().endswith(ext) for ext in _PATCH_LIKE) or "patch" in local_name.lower():
                patch_like_names.add(local_name)

        if not patch_like_names:
            return findings

        for fn_name, fn_node in iter_scopes(ctx):
            for node in walk(fn_node):
                if getattr(node, "kind", None) != "command":
                    continue
                words = command_words(node)
                if not words:
                    continue
                if words[0] in ("source", ".") or words[0] in _INTERPRETERS:
                    args = words[1:]
                elif words[0] == "chmod" and len(words) >= 3 and "+x" in words[1]:
                    args = [words[-1]]
                else:
                    continue
                for arg in args:
                    base = arg.rsplit("/", 1)[-1]
                    if base in patch_like_names or arg in patch_like_names:
                        findings.append(
                            _finding_at(
                                self,
                                ctx,
                                node.pos[0],
                                message=(
                                    f"{describe_scope(fn_name)} executes '{arg}', a source=() "
                                    f"entry named like a patch/data file, instead of applying "
                                    f"it with `patch`. This disguise (a fake 'patches' source "
                                    f"that is actually run) was used to smuggle a RAT into AUR "
                                    f"packages in 2025."
                                ),
                                remediation=(
                                    "Patch files should only ever be passed to `patch`/`git "
                                    "apply`, never sourced, chmod +x'd, or executed directly."
                                ),
                            )
                        )
        return findings
