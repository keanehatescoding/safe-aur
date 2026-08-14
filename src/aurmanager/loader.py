from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


class LoaderError(Exception):
    pass


@dataclass
class PackageFiles:
    pkgbuild: Path
    install_scripts: list[Path] = field(default_factory=list)
    patches: list[Path] = field(default_factory=list)


def resolve(path: Path) -> PackageFiles:
    path = Path(path)
    if path.is_dir():
        pkgbuild = path / "PKGBUILD"
        if not pkgbuild.is_file():
            raise LoaderError(f"no PKGBUILD found in {path}")
        directory = path
    elif path.is_file():
        if path.name != "PKGBUILD":
            raise LoaderError(f"expected a PKGBUILD file or a directory containing one, got {path}")
        pkgbuild = path
        directory = path.parent
    else:
        raise LoaderError(f"path does not exist: {path}")

    install_scripts = sorted(directory.glob("*.install"))
    patches = sorted(list(directory.glob("*.patch")) + list(directory.glob("*.diff")))
    return PackageFiles(pkgbuild=pkgbuild, install_scripts=install_scripts, patches=patches)
