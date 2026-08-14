from __future__ import annotations

import re
from typing import Iterable

from ..model import Finding, RuleContext, Severity
from ..parser.bash_ast import command_name, command_words, line_of, walk
from .base import Rule

_PACKAGE_MANAGERS = {"npm", "pip", "pip3", "go", "bun", "yarn", "pnpm"}
_INSTALL_VERBS = {"install", "add", "get"}
_INSTALL_HOOKS = ("post_install", "post_upgrade")

# pip's `==1.2.3`, npm/go's `@1.2.3` or `@v1.2.3` -- deliberately excludes npm/go
# "pins" like `@latest`/`@next` that aren't actually pinned to a fixed version.
_VERSION_PIN_RE = re.compile(r"(==\S|@=?v?\d)")

_NETWORK_COMMANDS = {"curl", "wget"}
_GIT_NETWORK_SUBCOMMANDS = {"ls-remote", "fetch", "pull", "clone"}

_URL_RE = re.compile(r"^(?:[\w+.-]+::)?(\w+)://(?:[^/@\s]+@)?([^/\s]+)")
_IP_LITERAL_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$")
_PASTE_HOSTS = {
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "transfer.sh",
    "0x0.st",
    "ix.io",
    "termbin.com",
    "file.io",
    "ghostbin.com",
    "dpaste.com",
}


def _line_for_source_entry(ctx: RuleContext, src: str) -> tuple[int | None, str | None]:
    idx = ctx.source.find(src)
    if idx == -1:
        return None, None
    line = line_of(idx, ctx.source)
    return line, ctx.source.splitlines()[line - 1].strip()


class INT001PkgverNetworkCall(Rule):
    """pkgver() is meant to derive a version string from sources already fetched by
    makepkg (e.g. `git describe` against an already-cloned checkout) -- it should
    never itself reach out over the network. A pkgver() that does (curl/wget, or
    `git ls-remote`/`fetch`/`pull`/`clone`) runs on every single invocation of
    makepkg, pacman -Syu, or any AUR helper that checks for updates, not just when
    actually building. No specific AUR incident is known to have used this exact
    mechanism (verified via web search); this is a generic heuristic, not
    incident-grounded like the other integrity rules."""

    rule_id = "INT001"
    category = "integrity"
    default_severity = Severity.MEDIUM

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        fn_node = ctx.functions.get("pkgver")
        if fn_node is None:
            return []
        findings: list[Finding] = []
        for node in walk(fn_node):
            if getattr(node, "kind", None) != "command":
                continue
            words = command_words(node)
            if not words:
                continue
            name = words[0]
            is_network = name in _NETWORK_COMMANDS or (
                name == "git" and len(words) > 1 and words[1] in _GIT_NETWORK_SUBCOMMANDS
            )
            if not is_network:
                continue
            line = line_of(node.pos[0], ctx.source)
            snippet = ctx.source.splitlines()[line - 1].strip() if line else None
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.default_severity,
                    message=(
                        f"pkgver() makes a network call ('{name}'), which runs on every "
                        f"makepkg/AUR-helper version check, not just when actually building."
                    ),
                    file=ctx.file,
                    line=line,
                    snippet=snippet,
                    remediation=(
                        "Derive the version from sources already fetched into $srcdir "
                        "(e.g. `git describe` against the checkout), not a live network call."
                    ),
                )
            )
        return findings


class INT002SuspiciousSourceHost(Rule):
    """A source=() URL pointing at a raw IP address or a known paste/ephemeral-file
    host (pastebin.com, transfer.sh, ...) instead of a recognizable upstream project
    host is a red flag -- legitimate upstream releases don't live on paste sites.
    Generalizes the disguise pattern from the 2025 Chaos RAT packages (an
    attacker-controlled host masquerading as a legitimate source), though this
    specific IP-literal/paste-host check isn't itself tied to a single cited
    incident."""

    rule_id = "INT002"
    category = "integrity"
    default_severity = Severity.MEDIUM

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        findings: list[Finding] = []
        for src in ctx.sources:
            m = _URL_RE.match(src)
            if not m:
                continue
            host = m.group(2).split(":")[0]
            reason = None
            if _IP_LITERAL_RE.match(m.group(2)):
                reason = "a raw IP address"
            elif host.lower() in _PASTE_HOSTS:
                reason = f"a paste/ephemeral-file host ({host})"
            if reason is None:
                continue
            line, snippet = _line_for_source_entry(ctx, src)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.default_severity,
                    message=f"source=() entry points at {reason} instead of a recognizable upstream project host: {src}",
                    file=ctx.file,
                    line=line,
                    snippet=snippet,
                    remediation="Source URLs should point at the actual upstream project's release infrastructure.",
                )
            )
        return findings


class INT003SkippedChecksumOnNetworkSource(Rule):
    """`SKIP` is a legitimate checksum entry for local files shipped alongside the
    PKGBUILD in the AUR git repo (already covered by AUR's own integrity) and for
    VCS sources (git+/svn+/hg+/bzr+ -- there's no fixed content to checksum, the VCS
    itself provides integrity), but for a plain network download it means makepkg
    will happily build from a tampered file with no integrity check at all."""

    rule_id = "INT003"
    category = "integrity"
    default_severity = Severity.MEDIUM

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        if not ctx.checksums or not ctx.sources:
            return []
        checksum_list = next(iter(ctx.checksums.values()))
        findings: list[Finding] = []
        for idx, src in enumerate(ctx.sources):
            if idx >= len(checksum_list):
                break
            url_part = src.split("::", 1)[-1]
            is_local = "://" not in url_part
            is_vcs = bool(re.match(r"^(?:git|svn|hg|bzr)\+", url_part))
            if is_local or is_vcs:
                continue
            if checksum_list[idx].strip().upper() != "SKIP":
                continue
            line, snippet = _line_for_source_entry(ctx, src)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.default_severity,
                    message=f"Checksum is SKIP for a network source ({src}) -- makepkg will build from a tampered download with no integrity check.",
                    file=ctx.file,
                    line=line,
                    snippet=snippet,
                    remediation="Provide a real checksum for any source fetched over the network.",
                )
            )
        return findings


class INT005InstallHookPullsUnpinnedDeps(Rule):
    """A post_install/post_upgrade hook silently running a package manager to pull
    down more code at install time bypasses the AUR review process entirely for
    whatever that dependency turns out to be -- exactly how the 2026 Atomic Arch
    campaign's `.install` hooks pulled the malicious `atomic-lockfile`/`js-digest`
    npm packages that dropped the actual infostealer/rootkit payload. See
    tests/fixtures/incidents/2026_atomic_arch_install_hook_and_obfuscation/
    SOURCE.md."""

    rule_id = "INT005"
    category = "integrity"
    default_severity = Severity.HIGH
    incident_refs = ("AUR-2026-atomic-arch",)

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        findings: list[Finding] = []
        for fn_name, fn_node in ctx.functions.items():
            if fn_name not in _INSTALL_HOOKS:
                continue
            for node in walk(fn_node):
                if getattr(node, "kind", None) != "command":
                    continue
                name = command_name(node)
                if name not in _PACKAGE_MANAGERS:
                    continue
                words = command_words(node)
                if len(words) < 2 or words[1] not in _INSTALL_VERBS:
                    continue

                specs = [w for w in words[2:] if not w.startswith("-")]
                all_pinned = bool(specs) and all(_VERSION_PIN_RE.search(s) for s in specs)

                line = line_of(node.pos[0], ctx.source)
                snippet = ctx.source.splitlines()[line - 1].strip() if line else None
                if all_pinned:
                    detail = "pins a specific version, but still fetches unaudited third-party code"
                else:
                    detail = "pulls additional, unpinned code"
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.default_severity,
                        message=(
                            f"'{fn_name}()' runs '{name} {words[1]}' to {detail} at install "
                            f"time -- this bypasses AUR review for whatever that dependency "
                            f"resolves to."
                        ),
                        file=ctx.file,
                        line=line,
                        snippet=snippet,
                        incident_ref=self.incident_refs[0],
                        remediation=(
                            "Package the actual runtime dependency properly (depends=()) "
                            "instead of fetching it via a package manager at install time."
                        ),
                    )
                )
        return findings
