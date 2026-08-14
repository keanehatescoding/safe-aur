# Incident: librewolf-fix-bin / firefox-patch-bin Chaos RAT packages (2025)

**Date:** uploaded 2025-07-16 by user "danikpapas"; removed 2025-07-18 after
community reports.
**Packages:** `librewolf-fix-bin`, `firefox-patch-bin`, `zen-browser-patched-bin`.

## Technique

Each package's PKGBUILD contained a `source=()` entry named to look like an ordinary
"patches" file, but the entry actually pointed at an attacker-controlled GitHub
repository. Instead of being applied with `patch`, the file was executed directly
during the build/install phase, dropping the CHAOS remote-access-trojan payload as a
binary disguised as `systemd-initd` in `/tmp`. The names of the packages themselves
("fix", "patch") were chosen to look like legitimate browser-security updates.

## Citations

- [Trojan Chaos RAT Discovered in Arch User Repository — HackMag](https://hackmag.com/news/aur-chaos)
- [Arch Linux pulls AUR packages that installed Chaos RAT malware — BleepingComputer](https://www.bleepingcomputer.com/news/security/arch-linux-pulls-aur-packages-that-installed-chaos-rat-malware/)
- [Malicious Chaos RAT Packages Discovered In Arch Linux AUR Repository — cybersecurefox](https://cybersecurefox.com/en/chaos-rat-malware-arch-linux-aur-security-alert/)

## Fixture notes

`PKGBUILD` in this directory is a **synthetic reconstruction**: a `source=()` entry
named `patches` that is `source`d directly in `build()` instead of being applied with
`patch`. Not the original malicious code. Exercises rule `RCE004` (disguised
patch-like source entry executed rather than applied) and, secondarily, `PER006`
(binary dropped into /tmp under a disguised systemd-* name).
