#!/usr/bin/env python3
"""Small desktop UI for Claude IP Guard."""

from __future__ import annotations

import importlib.util
import json
import os
import queue
import threading
from pathlib import Path
from typing import NamedTuple


def load_guard_module():
    module_path = Path(__file__).with_name("claude_ip_guard.py")
    spec = importlib.util.spec_from_file_location("claude_ip_guard", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = load_guard_module()


HINT_TEXT = "只有检测结果显示 SAFE，才打开 Claude Code；如果 ERROR 或 UNSAFE，宁可断开也不要换出口。"
ICON_FILE_NAME = "claude-ip-guard.png"
CONFIG_FILE_NAME = "settings.json"


class AppSettings(NamedTuple):
    proxy: str
    expected_ips: str
    expected_country: str
    timeout: float
    retries: int
    https_check: bool
    claude_trace_check: bool

    @property
    def expected_ip(self) -> str:
        ips = format_expected_ips(self.expected_ips)
        return ips[0] if ips else ""


DEFAULT_SETTINGS = AppSettings(
    proxy=guard.DEFAULT_PROXY,
    expected_ips=guard.DEFAULT_EXPECTED_IP,
    expected_country=guard.DEFAULT_EXPECTED_COUNTRY,
    timeout=10.0,
    retries=1,
    https_check=True,
    claude_trace_check=True,
)


class StatusModel(NamedTuple):
    state: str
    title: str
    details: str
    color: str


def default_config_path() -> Path:
    configured = os.environ.get("CLAUDE_IP_GUARD_CONFIG")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".claude-ip-guard" / CONFIG_FILE_NAME


def _float_setting(value, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _int_setting(value, default: int) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def load_settings(path: Path | None = None) -> AppSettings:
    path = path or default_config_path()
    data = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, json.JSONDecodeError):
            data = {}

    expected_ips = data.get("expected_ips")
    if expected_ips is None:
        expected_ips = data.get("expected_ip")

    return AppSettings(
        proxy=str(data.get("proxy") or DEFAULT_SETTINGS.proxy).strip(),
        expected_ips="\n".join(
            format_expected_ips(str(expected_ips or DEFAULT_SETTINGS.expected_ips))
        ),
        expected_country=str(
            data.get("expected_country") or DEFAULT_SETTINGS.expected_country
        )
        .strip()
        .upper(),
        timeout=_float_setting(data.get("timeout"), DEFAULT_SETTINGS.timeout),
        retries=_int_setting(data.get("retries"), DEFAULT_SETTINGS.retries),
        https_check=bool(data.get("https_check", DEFAULT_SETTINGS.https_check)),
        claude_trace_check=bool(
            data.get("claude_trace_check", DEFAULT_SETTINGS.claude_trace_check)
        ),
    )


def save_settings(settings: AppSettings, path: Path | None = None):
    path = path or default_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(settings._asdict(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def build_subtitle(settings: AppSettings) -> str:
    expected_ips = format_expected_ips(settings.expected_ips)
    default_ip = expected_ips[0] if expected_ips else "未设置"
    return (
        f"默认 IP: {default_ip} / {settings.expected_country}"
        f"    允许 {len(expected_ips)} 个 IP"
        f"    代理: {settings.proxy}"
    )


def format_expected_ips(value: str) -> list[str]:
    return guard.normalize_expected_ips(value)


def resource_path(file_name: str) -> Path:
    return Path(__file__).with_name(file_name)


def configure_window_icon(root, tk, icon_path: Path | None = None):
    icon_path = icon_path or resource_path(ICON_FILE_NAME)
    if not icon_path.exists():
        return None
    try:
        icon = tk.PhotoImage(file=str(icon_path))
        root.iconphoto(True, icon)
        return icon
    except Exception:
        return None


def build_display_rows(model: StatusModel, subtitle: str) -> list[tuple[str, str, str]]:
    rows = [
        ("title", model.title, model.color),
        ("subtitle", subtitle, "#374151"),
    ]
    for line in model.details.splitlines():
        if line.strip():
            rows.append(("detail", line, "#111827"))
    rows.append(("hint", HINT_TEXT, "#6b7280"))
    return rows


def build_status_model(decision, result, https_ip: str | None, claude_trace=None, risk=None) -> StatusModel:
    if decision.safe:
        title = "🟢 SAFE - 可以打开 Claude"
        color = "#0a7f3f"
        state = "safe"
    else:
        title = "🔴 UNSAFE - 不要打开 Claude"
        color = "#b42318"
        state = "unsafe"

    details = [
        decision.reason,
        f"Default IP: {result.ip}",
    ]
    if claude_trace:
        details.append(f"Claude AI IP: {claude_trace.ip} ({claude_trace.country_code or 'unknown'})")
    details.extend([
        f"Country: {result.country} ({result.country_code})",
        f"Location: {result.region} / {result.city}",
        f"ISP: {result.isp}",
        f"Org: {result.org}",
    ])
    if https_ip:
        details.append(f"HTTPS IP: {https_ip}")
    if risk:
        details.extend(guard.format_risk_lines(risk))
    return StatusModel(state=state, title=title, details="\n".join(details), color=color)


def build_error_model(message: str) -> StatusModel:
    return StatusModel(
        state="error",
        title="🔴 ERROR - 无法验证，别打开 Claude",
        details=message,
        color="#b45309",
    )


def build_checking_model() -> StatusModel:
    return StatusModel(
        state="checking",
        title="🔵 正在检测出口 IP...",
        details="请稍等。检测通过前不要打开 Claude Code。",
        color="#1d4ed8",
    )


def build_setup_required_model() -> StatusModel:
    return StatusModel(
        state="setup_required",
        title="🟡 需要先设置允许 IP",
        details="点击设置，填写你的 Claude 出口 IP。第一行会作为默认 IP。",
        color="#b45309",
    )


class ClaudeIpGuardApp:
    def __init__(self):
        import tkinter as tk

        self.tk = tk
        self.root = tk.Tk()
        self.root.title("Claude IP Guard")
        self.root.geometry("620x460")
        self.root.minsize(560, 420)
        self.root.configure(bg="#ffffff")
        self.window_icon = configure_window_icon(self.root, tk)

        self.results = queue.Queue()
        self.settings = load_settings()
        self.proxy = self.settings.proxy
        self.expected_ip = self.settings.expected_ip
        self.expected_country = self.settings.expected_country
        self.subtitle_text = build_subtitle(self.settings)
        self.display_buttons = []

        self._build_ui()
        if self.settings.expected_ip:
            self.apply_model(build_checking_model())
            self.root.after(200, self.run_check)
        else:
            self.apply_model(build_setup_required_model())
        self.root.after(100, self.consume_results)

    def _build_ui(self):
        tk = self.tk
        frame = tk.Frame(self.root, padx=24, pady=22, bg="#ffffff")
        frame.grid(row=0, column=0, sticky="nsew")
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        display_frame = tk.Frame(frame, bg="#ffffff")
        display_frame.grid(row=0, column=0, sticky="nsew")
        display_frame.columnconfigure(0, weight=1)

        for row_index in range(20):
            button = tk.Button(
                display_frame,
                text="",
                command=lambda: None,
                anchor="w",
                justify="left",
                relief="flat",
                borderwidth=0,
                highlightthickness=0,
                bg="#ffffff",
                activebackground="#ffffff",
                fg="#111827",
                padx=14,
                pady=5,
                takefocus=False,
            )
            button.grid(row=row_index, column=0, sticky="ew", pady=(0, 8))
            button.grid_remove()
            self.display_buttons.append(button)

        button_row = tk.Frame(frame, bg="#ffffff")
        button_row.grid(row=1, column=0, sticky="ew", pady=(16, 0))

        self.check_button = tk.Button(
            button_row,
            text="重新检测",
            command=self.run_check,
            width=14,
            height=2,
        )
        self.check_button.pack(side="left")

        self.settings_button = tk.Button(
            button_row,
            text="设置",
            command=self.open_settings,
            width=10,
            height=2,
        )
        self.settings_button.pack(side="left", padx=(12, 0))

    def configure_display_button(self, button, kind: str, text: str, color: str):
        if kind == "title":
            font = ("Helvetica", 22, "bold")
            pady = 8
        elif kind == "subtitle":
            font = ("Helvetica", 13)
            pady = 5
        elif kind == "hint":
            font = ("Helvetica", 13)
            pady = 7
        else:
            font = ("Menlo", 12)
            pady = 4
        button.configure(text=text, fg=color, font=font, pady=pady)

    def apply_model(self, model: StatusModel):
        rows = build_display_rows(model, self.subtitle_text)
        for button, row in zip(self.display_buttons, rows):
            kind, text, color = row
            self.configure_display_button(button, kind, text, color)
            button.grid()
        for button in self.display_buttons[len(rows) :]:
            button.grid_remove()
        self.check_button.configure(state="normal")

    def run_check(self):
        if not self.settings.expected_ip:
            self.apply_model(build_setup_required_model())
            return
        self.apply_model(build_checking_model())
        self.check_button.configure(state="disabled")

        def worker():
            try:
                decision, result, https_ip, claude_trace, risk = guard.check_proxy(
                    proxy=self.settings.proxy,
                    expected_ip=self.settings.expected_ips,
                    expected_country=self.settings.expected_country,
                    timeout=self.settings.timeout,
                    retries=self.settings.retries,
                    https_check=self.settings.https_check,
                    claude_trace_check=self.settings.claude_trace_check,
                )
                self.results.put(build_status_model(decision, result, https_ip, claude_trace, risk))
            except Exception as exc:
                self.results.put(build_error_model(str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def apply_settings(self, settings: AppSettings):
        self.settings = settings
        self.proxy = settings.proxy
        self.expected_ip = settings.expected_ip
        self.expected_country = settings.expected_country
        self.subtitle_text = build_subtitle(settings)
        save_settings(settings)
        self.run_check()

    def open_settings(self):
        tk = self.tk
        dialog = tk.Toplevel(self.root)
        dialog.title("设置")
        dialog.resizable(False, False)
        dialog.configure(bg="#ffffff")
        dialog.transient(self.root)
        dialog.grab_set()

        fields = tk.Frame(dialog, padx=22, pady=18, bg="#ffffff")
        fields.grid(row=0, column=0, sticky="nsew")

        variables = {
            "proxy": tk.StringVar(value=self.settings.proxy),
            "expected_country": tk.StringVar(value=self.settings.expected_country),
            "timeout": tk.StringVar(value=str(self.settings.timeout)),
            "retries": tk.StringVar(value=str(self.settings.retries)),
        }
        https_check = tk.BooleanVar(value=self.settings.https_check)
        claude_trace_check = tk.BooleanVar(value=self.settings.claude_trace_check)

        labels = [
            ("代理", "proxy"),
            ("国家代码", "expected_country"),
            ("超时秒数", "timeout"),
            ("重试次数", "retries"),
        ]
        tk.Label(fields, text="允许 IP", anchor="nw", bg="#ffffff").grid(
            row=0, column=0, sticky="nw", pady=(0, 8)
        )
        expected_ips_text = tk.Text(fields, width=32, height=4)
        expected_ips_text.insert("1.0", self.settings.expected_ips)
        expected_ips_text.grid(row=0, column=1, sticky="ew", padx=(12, 0), pady=(0, 8))
        tk.Label(
            fields,
            text="第一行作为默认 IP；每行或逗号分隔一个允许 IP。",
            fg="#6b7280",
            bg="#ffffff",
            anchor="w",
        ).grid(row=1, column=1, sticky="ew", padx=(12, 0), pady=(0, 8))

        for row, (label, key) in enumerate(labels, start=2):
            tk.Label(fields, text=label, anchor="w", bg="#ffffff").grid(
                row=row, column=0, sticky="w", pady=(0, 8)
            )
            tk.Entry(fields, textvariable=variables[key], width=32).grid(
                row=row, column=1, sticky="ew", padx=(12, 0), pady=(0, 8)
            )

        tk.Checkbutton(
            fields,
            text="启用 HTTPS 二次校验",
            variable=https_check,
            bg="#ffffff",
            activebackground="#ffffff",
        ).grid(row=len(labels) + 2, column=0, columnspan=2, sticky="w", pady=(4, 4))
        tk.Checkbutton(
            fields,
            text="使用 Claude AI 出口 IP 校验",
            variable=claude_trace_check,
            bg="#ffffff",
            activebackground="#ffffff",
        ).grid(row=len(labels) + 3, column=0, columnspan=2, sticky="w", pady=(0, 12))

        message = tk.Label(fields, text="", fg="#b42318", bg="#ffffff", anchor="w")
        message.grid(row=len(labels) + 4, column=0, columnspan=2, sticky="ew")

        button_row = tk.Frame(fields, bg="#ffffff")
        button_row.grid(row=len(labels) + 5, column=0, columnspan=2, sticky="e", pady=(14, 0))

        def save_from_dialog():
            try:
                settings = AppSettings(
                    proxy=variables["proxy"].get().strip(),
                    expected_ips="\n".join(
                        format_expected_ips(expected_ips_text.get("1.0", "end").strip())
                    ),
                    expected_country=variables["expected_country"].get().strip().upper(),
                    timeout=float(variables["timeout"].get()),
                    retries=max(0, int(variables["retries"].get())),
                    https_check=https_check.get(),
                    claude_trace_check=claude_trace_check.get(),
                )
            except ValueError:
                message.configure(text="超时和重试次数需要填数字。")
                return
            if not settings.proxy or not settings.expected_ip or not settings.expected_country:
                message.configure(text="代理、允许 IP 和国家代码不能为空。")
                return
            self.apply_settings(settings)
            dialog.destroy()

        tk.Button(button_row, text="取消", command=dialog.destroy, width=8).pack(side="right")
        tk.Button(button_row, text="保存", command=save_from_dialog, width=8).pack(
            side="right", padx=(0, 10)
        )

    def consume_results(self):
        try:
            while True:
                self.apply_model(self.results.get_nowait())
        except queue.Empty:
            pass
        self.root.after(100, self.consume_results)

    def run(self):
        self.root.mainloop()


def main():
    ClaudeIpGuardApp().run()


if __name__ == "__main__":
    main()
