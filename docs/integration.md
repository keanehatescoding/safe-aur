# Running aur-manager automatically before a build

`aur-manager scan`/`diff` are useless if a user has to remember to run them —
the whole point is catching a malicious PKGBUILD *before* `makepkg` executes
it. This document covers wiring `aur-manager` into the normal AUR install
workflow so scanning isn't opt-in.

`makepkg` itself has no pre-build hook mechanism — `prepare()` runs as part of
the untrusted build itself, so it can't be used as a gate. Integration has to
happen at the AUR helper layer instead. The two most common helpers both
support this natively as of 2026:

## paru

paru has a documented `PreBuildCommand` config option that runs a command
before each package builds. Merge [`paru.conf.snippet`](../integrations/paru.conf.snippet)
into `~/.config/paru/paru.conf`:

```ini
[bin]
PreBuildCommand = aur-manager scan --fail-on high .
```

It goes under `[bin]`, not `[options]` — despite reading like a general option,
it's parsed by `parse_bin()` (`src/config.rs`). Getting the section wrong fails
loudly (`error: unknown option 'PreBuildCommand' in section [options]`) rather
than silently doing nothing, but it's an easy mistake: an earlier version of
this doc had it under `[options]` and was wrong until live-tested against a
real paru install.

**Verified behavior** — confirmed both by reading paru v2.1.0's source
(`src/install.rs:pre_build_command`, `src/exec.rs:command`; `paru.conf(5)`
documents the option but not its exit-code behavior) *and* by live-testing
against a real, installed paru v2.1.0: the command runs via `sh -c` with its
working directory set to each package's PKGBUILD directory, and a non-zero
exit is propagated as an error that aborts paru's *entire* operation — not
just the flagged package.

This is genuinely operation-wide, not per-package, because of how the source
is structured: `PreBuildCommand` runs for every package in the batch, in one
loop, entirely *before* any of them enters the actual build phase (a separate,
later loop). Confirmed with a 3-package `paru -B` batch (package A clean,
package B containing an RCE001-triggering construct, package C clean): A
scanned clean first, B got flagged and aborted the run, and **C's hook was
never even reached — but neither was A's build, despite A having already
passed its own scan**. No `src/` directory was created for any of the three
packages. `aur-manager scan`'s own exit code (`1` at or above `--fail-on`) is
exactly what this needs — no wrapper script required.

Re-verify this against your installed paru version before relying on it as a
hard gate in an unattended context; behavior not covered by `paru.conf(5)`
itself could change in a future release.

## yay (v13+)

yay has a Lua hook system (`~/.config/yay/init.lua`). Copy
[`yay-init.lua`](../integrations/yay-init.lua) there (or merge its
`AURPreInstall` block into an existing `init.lua`):

```lua
local function shell_quote(s)
  return "'" .. s:gsub("'", "'\\''") .. "'"
end

yay.create_autocmd("AURPreInstall", {
  desc = "run aur-manager scan before building",
  callback = function(event)
    local cmd = "aur-manager scan --fail-on high " .. shell_quote(event.data.dir)
    if os.execute(cmd) ~= 0 then
      yay.abort("aur-manager flagged " .. event.data.base .. " -- aborting install")
    end
  end,
})
```

(`shell_quote` is included above so this block is copy-pasteable on its own — if
you're merging into an existing `init.lua` that already defines it, or merging
the whole [`yay-init.lua`](../integrations/yay-init.lua) file directly, don't
duplicate the definition.)

`AURPreInstall` fires once per package base, after the PKGBUILD is
downloaded, before the review/edit menu and before any build. `yay.abort()`
stops the whole operation cleanly.

**One non-obvious gotcha, verified by reading gopher-lua's source directly**
(`github.com/yuin/gopher-lua`, the Lua interpreter yay embeds): its
`os.execute` returns a plain number — `0` on success, `1` on failure — not
Lua's standard `true`/`nil`/exit-reason triple. The idiomatic-looking
`if not os.execute(cmd) then` is silently wrong here, since `0` is truthy in
Lua; it would never detect a failure. The snippet above uses
`os.execute(cmd) ~= 0`, which is correct for yay's specific runtime.

## Other helpers / makepkg directly

Neither of the above applies, so the fallback is a shell function that wraps
whatever you normally invoke, e.g. in your shell rc:

```sh
aursafe() {
  if [ -f PKGBUILD ]; then
    aur-manager scan --fail-on high . || return 1
  fi
  makepkg "$@"
}
```

This is genuinely worse than the native hooks above — it only fires if you
remember to type `aursafe` instead of `makepkg`, which is exactly the
opt-in problem this document is trying to avoid — so treat it as a stopgap,
not the target state.

## Exit code contract these hooks rely on

`aur-manager scan`/`diff` exit `1` when the (diff) verdict is at or above
`--fail-on` (default `high`), `0` otherwise, `2` on a usage/loader error (see
the main [README](../README.md#exit-codes)). All snippets above pin
`--fail-on high` explicitly rather than relying on the default, so a future
default change here doesn't silently change what gates a build.
