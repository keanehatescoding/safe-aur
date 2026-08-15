from __future__ import annotations

from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"
INCIDENTS_DIR = FIXTURES_DIR / "incidents"
BENIGN_DIR = FIXTURES_DIR / "benign"


def incident_fixture_dirs() -> list[Path]:
    if not INCIDENTS_DIR.is_dir():
        return []
    return sorted(p for p in INCIDENTS_DIR.iterdir() if p.is_dir())


def benign_fixture_dirs() -> list[Path]:
    if not BENIGN_DIR.is_dir():
        return []
    return sorted(p for p in BENIGN_DIR.iterdir() if p.is_dir())
