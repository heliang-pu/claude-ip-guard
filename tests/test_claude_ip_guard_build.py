import subprocess
from pathlib import Path


def test_linux_bundle_uses_relative_launcher():
    repo_root = Path(__file__).resolve().parents[1]

    subprocess.run(
        [str(repo_root / "tools" / "build_claude_ip_guard_app.py")],
        cwd=repo_root,
        check=True,
    )

    launcher = repo_root / "dist" / "claude-ip-guard-linux" / "claude-ip-guard"
    desktop = repo_root / "dist" / "claude-ip-guard-linux" / "claude-ip-guard.desktop"

    assert launcher.exists()
    assert desktop.exists()
    launcher_text = launcher.read_text(encoding="utf-8")
    desktop_text = desktop.read_text(encoding="utf-8")

    assert "SCRIPT_DIR=" in launcher_text
    assert "/Users/" not in launcher_text
    assert "Exec=claude-ip-guard" in desktop_text


def test_macos_bundle_uses_system_python_with_tk():
    repo_root = Path(__file__).resolve().parents[1]

    subprocess.run(
        [str(repo_root / "tools" / "build_claude_ip_guard_app.py")],
        cwd=repo_root,
        check=True,
    )

    launcher = repo_root / "dist" / "Claude IP Guard.app" / "Contents" / "MacOS" / "Claude IP Guard"
    launcher_text = launcher.read_text(encoding="utf-8")

    assert "exec /usr/bin/python3" in launcher_text
    assert "/usr/bin/env python3" not in launcher_text


def test_macos_bundle_declares_and_copies_app_icon():
    repo_root = Path(__file__).resolve().parents[1]

    subprocess.run(
        [str(repo_root / "tools" / "build_claude_ip_guard_app.py")],
        cwd=repo_root,
        check=True,
    )

    contents = repo_root / "dist" / "Claude IP Guard.app" / "Contents"
    info_plist = (contents / "Info.plist").read_text(encoding="utf-8")

    assert "<key>CFBundleIconFile</key>" in info_plist
    assert "<string>claude-ip-guard.icns</string>" in info_plist
    assert (contents / "Resources" / "claude-ip-guard.icns").exists()
    assert (contents / "Resources" / "claude-ip-guard.png").exists()


def test_linux_tarball_is_created():
    repo_root = Path(__file__).resolve().parents[1]

    subprocess.run(
        [str(repo_root / "tools" / "build_claude_ip_guard_app.py")],
        cwd=repo_root,
        check=True,
    )

    assert (repo_root / "dist" / "claude-ip-guard-linux.tar.gz").exists()
