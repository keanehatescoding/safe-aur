# Benign fixtures

These are **representative synthetic examples** of ordinary, non-malicious PKGBUILDs
-- written to exercise common legitimate patterns that a naive rule could easily
mistake for something suspicious (compiling from source, `pip install` as a genuine
build-time dependency step, packaging a systemd unit file, deriving a version with
`git describe` in `pkgver()`). They are not verbatim files vendored from real AUR/Arch
packages.

`tests/test_engine_and_report.py::test_benign_fixture_has_no_high_severity_findings`
runs the full rule set against every fixture here and asserts nothing at or above
MEDIUM severity fires -- this is the project's false-positive regression guard.

| Fixture | What it exercises |
|---|---|
| `simple-c-program/` | A minimal `./configure && make && make install` package -- the baseline "nothing here should ever fire" case. |
| `python-package-with-systemd-unit/` | `pip install` as a genuine build-time step (not smuggled into a `.install` hook, so `INT005` shouldn't fire), plus packaging a `.service` file under `$pkgdir` (so `PER003` shouldn't mistake shipping a unit for enabling one). |
| `git-versioned-package/` | `pkgver()` using `git describe` against already-fetched sources -- a very common, legitimate PKGBUILD idiom. |
