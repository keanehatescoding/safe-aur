# Incident: openconnect-sso and the August 2026 orphan-adoption wave

**Date:** malicious commit dated 2026-07-29; Arch Linux disabled AUR package adoption
on 2026-07-30 and paused all AUR pushes on 2026-08-01 while investigating.
**Package:** `openconnect-sso` (orphaned, re-adopted), part of a wave naming at least
89 packages (e.g. `boringssl-git`, `icloudpd`, `windscribe-cli-v2-bin`).

## Technique

A binary named `validator` was added to the package's `source=()` array and then
invoked with `sudo` during the build/packaging path. Running under sudo turned what
should be an unprivileged build step into a privileged execution surface. The payload
was a two-stage infection chain (a loader with anti-analysis checks, then a
Tor-delivered Rust infostealer/RAT with SSH-worm behavior) reusing C2 infrastructure
tied to the earlier "Atomic Arch" campaign.

## Citations

- [Arch AUR's August malware wave: openconnect-sso and 89 named packages — Corgea](https://corgea.com/research/arch-aur-openconnect-sso-malware-wave-august-2026)
- [Arch Linux disables AUR package adoption to stop malware flood — BleepingComputer](https://www.bleepingcomputer.com/news/security/arch-linux-disables-aur-package-adoption-to-stop-malware-flood/)
- [Arch AUR Malware Wave: Check openconnect-sso Exposure — Gridinsoft](https://blog.gridinsoft.com/arch-aur-openconnect-sso-malware/)

## Fixture notes

`PKGBUILD` in this directory is a **synthetic reconstruction** of the technique (a
`source=()` binary invoked with `sudo` inside `build()`) -- not the original
malicious code. It exists to exercise rule `PRV001` (sudo/doas/pkexec inside a
build-lifecycle function).
