#!/usr/bin/env python3
"""Build a source distribution; never sweep generated VPN state into an archive."""
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


def build() -> Path:
    root = Path(__file__).resolve().parents[1]
    files = [root / name for name in (
        "README.md", "MyVPN.cmd", "Connect.cmd", "Disconnect.cmd", ".gitignore"
    )]
    suffixes = {".ps1", ".psm1", ".sh", ".md", ".py"}
    for folder in ("windows", "server", "docs", "tests", "tools"):
        base = root / folder
        if base.is_symlink():
            raise RuntimeError(f"Refusing linked packaging directory: {folder}")
        for path in sorted(base.rglob("*")):
            if path.is_symlink():
                raise RuntimeError("Refusing linked packaging input")
            if path.is_file() and path.suffix in suffixes:
                files.append(path)
    destination = root / "dist" / "MyVPN-windows.zip"
    destination.parent.mkdir(exist_ok=True)
    with ZipFile(destination, "w", compression=ZIP_DEFLATED) as archive:
        for path in files:
            if path.is_symlink():
                raise RuntimeError("Refusing linked packaging input")
            content = path.read_bytes()
            if path.suffix == ".cmd":
                content = content.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            archive.writestr("MyVPN/" + path.relative_to(root).as_posix(), content)
    print(f"Created {destination} ({len(files)} files; no VPN profiles)")
    return destination


if __name__ == "__main__":
    build()
