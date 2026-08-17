from __future__ import annotations

import re
from typing import Iterable

from ..model import Finding, RuleContext, Severity
from ..parser.bash_ast import describe_scope, line_and_snippet
from .base import Rule

_NETWORK_UPLOAD_RE = re.compile(
    r"\bcurl\b[^\n]*(?:-d\b|--data|-F\b|--form|-T\b|--upload-file)"
    r"|\bwget\b[^\n]*--post-(?:data|file)"
    r"|\b(?:nc|ncat|netcat)\b"
)

_SSH_READ_RE = re.compile(r"\b(?:cat|cp|tar|find|scp|rsync)\b[^\n]*~?/?\.ssh\b")
_GNUPG_READ_RE = re.compile(r"\b(?:cat|cp|tar|find|scp|rsync)\b[^\n]*~?/?\.gnupg\b")
_BROWSER_STORE_RE = re.compile(
    r"\b(?:cat|cp|tar|find|scp|rsync)\b[^\n]*"
    r"(?:\.mozilla/[^\s]*(?:cookies\.sqlite|logins\.json|key4\.db)"
    r"|\.config/google-chrome/[^\s]*(?:Login Data|Cookies)"
    r"|\.config/(?:chromium|BraveSoftware)/[^\s]*(?:Login Data|Cookies))"
)
_ENV_DUMP_RE = re.compile(r"\b(?:env|printenv|export\s+-p)\b")
_DEV_CLOUD_CRED_READ_RE = re.compile(
    r"\b(?:cat|cp|tar|find|scp|rsync)\b[^\n]*"
    r"(?:~?/?\.aws/(?:credentials|config)\b"
    r"|~?/?\.config/gcloud/"
    r"|~?/?\.azure/"
    r"|~?/?\.docker/config\.json\b"
    r"|~?/?\.npmrc\b"
    r"|~?/?\.git-credentials\b"
    r"|~?/?\.netrc\b"
    r"|~?/?\.kube/config\b)"
)


class _ReadThenUploadRule(Rule):
    read_pattern: re.Pattern
    what: str

    def _scan(self, ctx: RuleContext, scope_label: str, body_text: str, base_offset: int) -> list[Finding]:
        read_match = self.read_pattern.search(body_text)
        upload_match = _NETWORK_UPLOAD_RE.search(body_text)
        if not (read_match and upload_match):
            return []
        offset = base_offset + read_match.start()
        line, snippet = line_and_snippet(offset, ctx.source)
        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.default_severity,
                message=(
                    f"{scope_label} reads {self.what} and also makes an outbound "
                    f"network upload -- looks like credential exfiltration."
                ),
                file=ctx.file,
                line=line,
                snippet=snippet,
                incident_ref=self.incident_refs[0] if self.incident_refs else None,
                remediation=f"A package has no legitimate reason to read {self.what} and phone home.",
            )
        ]

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        findings: list[Finding] = []
        for fn_name, fn_node in ctx.functions.items():
            if fn_node is None:
                continue
            body_text = ctx.source[fn_node.pos[0] : fn_node.pos[1]]
            findings.extend(self._scan(ctx, describe_scope(fn_name), body_text, fn_node.pos[0]))

        if ctx.module_scope is not None:
            # module_scope_source has every function body masked out, so this only
            # matches genuinely top-level code -- PKGBUILD/.install top-level
            # statements run immediately when the file is sourced, so they're not
            # somehow safer than code inside build()/package().
            findings.extend(
                self._scan(ctx, describe_scope("<module scope>"), ctx.module_scope_source, 0)
            )
        return findings


class EXF001SshKeyExfiltration(_ReadThenUploadRule):
    """Reading ~/.ssh/ and making a network call in the same function is the classic
    SSH-key-theft shape -- the mechanism the 2026 Atomic Arch infostealer used to
    steal SSH credentials for lateral movement."""

    rule_id = "EXF001"
    category = "exfiltration"
    default_severity = Severity.CRITICAL
    incident_refs = ("AUR-2026-atomic-arch",)
    read_pattern = _SSH_READ_RE
    what = "~/.ssh/"


class EXF002GnupgExfiltration(_ReadThenUploadRule):
    """Same shape as EXF001, targeting GPG keys instead of SSH keys."""

    rule_id = "EXF002"
    category = "exfiltration"
    default_severity = Severity.CRITICAL
    read_pattern = _GNUPG_READ_RE
    what = "~/.gnupg/"


class EXF003BrowserCredentialExfiltration(_ReadThenUploadRule):
    """Same shape again, targeting browser cookie/login-credential stores -- also
    part of the 2026 Atomic Arch infostealer's credential-harvesting behavior."""

    rule_id = "EXF003"
    category = "exfiltration"
    default_severity = Severity.CRITICAL
    incident_refs = ("AUR-2026-atomic-arch",)
    read_pattern = _BROWSER_STORE_RE
    what = "a browser's cookie/login-credential store"


class EXF004EnvironmentExfiltration(_ReadThenUploadRule):
    """Dumping the environment (which commonly holds API tokens/secrets in CI-like
    build contexts) and then uploading it is a lower-confidence but still worth
    flagging exfiltration shape."""

    rule_id = "EXF004"
    category = "exfiltration"
    default_severity = Severity.HIGH
    read_pattern = _ENV_DUMP_RE
    what = "the process environment"


class EXF005DeveloperCloudCredentialExfiltration(_ReadThenUploadRule):
    """Same shape again, targeting developer/CI and cloud-provider credential
    files -- AWS/GCP/Azure credentials, Docker registry auth, npm/git tokens,
    and kubeconfig. The 2026 Atomic Arch infostealer's payload was documented
    to steal exactly this alongside the SSH keys EXF001 already covers: 'SSH
    keys, and GitHub/npm/cloud/Docker tokens' (see
    tests/fixtures/incidents/2026_atomic_arch_install_hook_and_obfuscation/
    SOURCE.md)."""

    rule_id = "EXF005"
    category = "exfiltration"
    default_severity = Severity.CRITICAL
    incident_refs = ("AUR-2026-atomic-arch",)
    read_pattern = _DEV_CLOUD_CRED_READ_RE
    what = "developer/cloud credential files (AWS/GCP/Azure, Docker, npm, git, or kubeconfig)"
