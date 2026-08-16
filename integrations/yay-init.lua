-- aur-manager pre-build hook for yay (v13+, Lua hook system).
--
-- Install: merge this into ~/.config/yay/init.lua (create the file if it
-- doesn't exist). Requires `aur-manager` to be on PATH.
--
-- AURPreInstall fires once per package base after the PKGBUILD is
-- downloaded/merged, before the clean/diff/edit menus and before any build.
-- yay.abort() stops the whole operation cleanly (no Lua traceback).
--
-- Note: yay embeds gopher-lua (github.com/yuin/gopher-lua), whose os.execute
-- returns a plain number -- 0 on success, 1 on failure/non-zero exit -- NOT
-- Lua's standard true/nil/exit-reason triple. `if not os.execute(...)` would
-- silently never fire, since 0 is truthy in Lua. Verified against gopher-lua's
-- oslib.go directly; don't "fix" this to the standard-Lua idiom.

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
