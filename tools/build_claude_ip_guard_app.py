#!/usr/bin/env python3
"""Build a lightweight macOS app bundle and Linux launcher for Claude IP Guard."""

from __future__ import annotations

import os
import shutil
import tarfile
from pathlib import Path


APP_NAME = "Claude IP Guard"
ICON_PNG = "claude-ip-guard.png"
ICON_ICNS = "claude-ip-guard.icns"


def write_text(path: Path, content: str, executable: bool = False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if executable:
        path.chmod(path.stat().st_mode | 0o755)


def build(repo_root: Path) -> Path:
    dist_dir = repo_root / "dist"
    for old_linux_artifact in (
        dist_dir / "claude-ip-guard",
        dist_dir / "claude-ip-guard.desktop",
    ):
        if old_linux_artifact.exists():
            old_linux_artifact.unlink()

    app_path = dist_dir / f"{APP_NAME}.app"
    if app_path.exists():
        shutil.rmtree(app_path)

    contents = app_path / "Contents"
    macos = contents / "MacOS"
    resources = contents / "Resources"
    macos.mkdir(parents=True)
    resources.mkdir(parents=True)

    shutil.copy2(repo_root / "tools" / "claude_ip_guard.py", resources / "claude_ip_guard.py")
    shutil.copy2(repo_root / "tools" / "claude_ip_guard_app.py", resources / "claude_ip_guard_app.py")
    shutil.copy2(repo_root / "tools" / ICON_PNG, resources / ICON_PNG)
    shutil.copy2(repo_root / "tools" / ICON_ICNS, resources / ICON_ICNS)

    write_text(
        contents / "Info.plist",
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>Claude IP Guard</string>
  <key>CFBundleIdentifier</key>
  <string>local.claude-ip-guard</string>
  <key>CFBundleName</key>
  <string>Claude IP Guard</string>
  <key>CFBundleDisplayName</key>
  <string>Claude IP Guard</string>
  <key>CFBundleIconFile</key>
  <string>claude-ip-guard.icns</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleVersion</key>
  <string>1.0</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0</string>
</dict>
</plist>
""",
    )

    write_text(
        macos / "Claude IP Guard",
        """#!/bin/sh
RESOURCE_DIR="$(cd "$(dirname "$0")/../Resources" && pwd)"
exec /usr/bin/python3 "$RESOURCE_DIR/claude_ip_guard_app.py"
""",
        executable=True,
    )

    linux_dir = dist_dir / "claude-ip-guard-linux"
    if linux_dir.exists():
        shutil.rmtree(linux_dir)
    linux_dir.mkdir(parents=True)
    shutil.copy2(repo_root / "tools" / "claude_ip_guard.py", linux_dir / "claude_ip_guard.py")
    shutil.copy2(
        repo_root / "tools" / "claude_ip_guard_app.py",
        linux_dir / "claude_ip_guard_app.py",
    )
    shutil.copy2(repo_root / "tools" / ICON_PNG, linux_dir / ICON_PNG)

    linux_launcher = linux_dir / "claude-ip-guard"
    write_text(
        linux_launcher,
        """#!/bin/sh
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec /usr/bin/env python3 "$SCRIPT_DIR/claude_ip_guard_app.py"
""",
        executable=True,
    )

    write_text(
        linux_dir / "claude-ip-guard.desktop",
        """[Desktop Entry]
Type=Application
Name=Claude IP Guard
Comment=Check the fixed Claude egress IP before opening Claude Code
Exec=claude-ip-guard
Terminal=false
Categories=Utility;Network;
""",
    )

    tarball = dist_dir / "claude-ip-guard-linux.tar.gz"
    if tarball.exists():
        tarball.unlink()
    with tarfile.open(tarball, "w:gz") as archive:
        archive.add(linux_dir, arcname=linux_dir.name)

    return app_path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    app_path = build(repo_root)
    print(app_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
