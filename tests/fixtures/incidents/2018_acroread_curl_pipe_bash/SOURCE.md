# Incident: acroread AUR package hijack (2018)

**Date:** June–July 2018
**Package:** `acroread` (orphaned AUR package, adopted by a malicious actor under the
username "xeactor")

## Technique

The user adopted the orphaned `acroread` PKGBUILD and modified it to add a `curl`
command that fetched a remote script and piped it directly into `bash`, executing it
without any integrity check. The payload reconfigured `systemd` to re-run itself
periodically, establishing persistence. Two other orphaned packages recently adopted
by the same account were found modified with the same pattern. The compromise was
discovered by the community, AUR maintainers reverted the malicious commits and
suspended the account.

## Citations

- [Malware found in the Arch Linux AUR repository — LWN.net](https://lwn.net/Articles/759461/)
- [Malicious Software Packages Found On Arch Linux User Repository — The Hacker News](https://thehackernews.com/2018/07/arch-linux-aur-malware.html)
- [Malware Found in Arch Linux AUR Package Repository — BleepingComputer](https://www.bleepingcomputer.com/news/security/malware-found-in-arch-linux-aur-package-repository/)
- [Arch Linux AUR Repository Compromised — SecurityWeek](https://www.securityweek.com/arch-linux-aur-repository-compromised/)

## Fixture notes

`PKGBUILD` in this directory is a **synthetic reconstruction** of the technique
(curl output piped directly into bash inside a build-lifecycle function) — it is not
the original malicious code, and the fetched URL is a non-resolving placeholder. It
exists to exercise rule `RCE001` (curl/wget piped into an interpreter) as a
regression test.
