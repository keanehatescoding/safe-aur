# Incident: "Atomic Arch" campaign (June 2026)

**Date:** disclosed 2026-06-11/12; malicious activity window approximately
2026-06-09 through 2026-06-12.
**Scope:** ~1,500 orphaned AUR packages adopted and modified; independent trackers
catalogued 400+ confirmed within a day.

## Technique

Attackers systematically adopted orphaned AUR packages and modified their `.install`
scripts' `post_install`/`post_upgrade` hooks to silently run `npm install
atomic-lockfile` (and Bun-based variants pulling `js-digest`/`lockfile-js` in a
second wave). The malicious npm package's lifecycle script executed a Linux ELF
infostealer written in Rust, with optional eBPF-based rootkit capability to hide its
own process, files, and network connections from admin tooling on systems where it
gained root. Stolen credentials included SSH keys, and GitHub/npm/cloud/Docker
tokens. Some reported obfuscated samples in this wave used a
`echo '<base64>' | base64 -d | bash` shape to hide the actual payload.

## Citations

- [Over 400 Arch Linux AUR Packages Hijacked to Deploy Infostealer and eBPF Rootkit — The Hacker News](https://thehackernews.com/2026/06/over-400-arch-linux-aur-packages.html)
- [Atomic Arch turned orphaned AUR packages into npm and Bun malware launchers — Corgea](https://corgea.com/research/atomic-arch-aur-atomic-lockfile-js-digest-ebpf-rootkit)
- [Atomic Arch npm Campaign Adds Malicious Dependency — Sonatype](https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency)
- [Atomic Arch: AUR Supply Chain Attack Deploys eBPF Rootkit — Cloud Security Alliance](https://labs.cloudsecurityalliance.org/research/csa-research-note-aur-supply-chain-ebpf-rootkit-20260614-csa/)

## Fixture notes

`package.install` in this directory is a **synthetic reconstruction**: a
`post_install()` hook that runs `npm install` of an unpinned package, plus a
`base64 -d | bash` one-liner modeled on the obfuscated variant reported in this
campaign. Not the original malicious code. Exercises rules `INT005` (.install hook
pulling unpinned deps via a package manager) and `OBF001` (base64-decode-then-exec).
