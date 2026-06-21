import importlib.util
from pathlib import Path


APP_PATH = Path(__file__).resolve().parents[1] / "tools" / "claude_ip_guard_app.py"
GUARD_PATH = Path(__file__).resolve().parents[1] / "tools" / "claude_ip_guard.py"


def load_modules():
    guard_spec = importlib.util.spec_from_file_location("claude_ip_guard", GUARD_PATH)
    guard = importlib.util.module_from_spec(guard_spec)
    guard_spec.loader.exec_module(guard)

    app_spec = importlib.util.spec_from_file_location("claude_ip_guard_app", APP_PATH)
    app = importlib.util.module_from_spec(app_spec)
    app_spec.loader.exec_module(app)
    return app, guard


def test_build_status_model_marks_safe_state():
    app, guard = load_modules()
    result = guard.IpCheckResult(
        ip="203.0.113.10",
        country_code="US",
        country="United States",
        region="New Jersey",
        city="Hackensack",
        isp="Cogent Communications",
        org="Fiberpower LLC",
        source="ip-api",
    )
    decision = guard.Decision(True, guard.EXIT_SAFE, "static IP verified")

    claude_trace = guard.CloudflareTrace("203.0.113.10", "US", "claude.ai/cdn-cgi/trace")

    risk = guard.IpRiskResult(
        ip="203.0.113.10",
        trust_score=90,
        ip_type_label="家庭住宅IP",
        company_type="isp",
        asn=174,
        as_organization="Cogent Communications, LLC",
        is_vpn=False,
        is_proxy=False,
        is_tor=False,
        is_crawler=False,
        is_abuser=False,
    )

    model = app.build_status_model(decision, result, "203.0.113.10", claude_trace, risk)

    assert model.state == "safe"
    assert model.title.startswith("🟢 SAFE")
    assert "可以打开 Claude" in model.title
    assert "203.0.113.10" in model.details
    assert "Claude AI IP: 203.0.113.10 (US)" in model.details
    assert "Trust Score: 90" in model.details
    assert "IP Type: 家庭住宅IP (isp)" in model.details
    assert "VPN: no" in model.details


def test_build_status_model_marks_unsafe_state():
    app, guard = load_modules()
    result = guard.IpCheckResult(
        ip="54.92.69.117",
        country_code="JP",
        country="Japan",
        region="Tokyo",
        city="Tokyo",
        isp="Amazon Technologies Inc",
        org="Amazon",
        source="ip-api",
    )
    decision = guard.Decision(False, guard.EXIT_UNSAFE, "expected IP 203.0.113.10")

    model = app.build_status_model(decision, result, None, None, None)

    assert model.state == "unsafe"
    assert model.title.startswith("🔴 UNSAFE")
    assert "不要打开 Claude" in model.title
    assert "54.92.69.117" in model.details


def test_build_checking_model_warns_not_to_open_claude():
    app, _ = load_modules()

    model = app.build_checking_model()

    assert model.state == "checking"
    assert model.title.startswith("🔵")
    assert "正在检测" in model.title
    assert "不要打开 Claude Code" in model.details


def test_build_error_model_uses_red_status_symbol():
    app, _ = load_modules()

    model = app.build_error_model("request failed")

    assert model.state == "error"
    assert model.title.startswith("🔴 ERROR")
    assert "request failed" in model.details


def test_build_setup_required_model_tells_user_to_configure_ip():
    app, _ = load_modules()

    model = app.build_setup_required_model()

    assert model.state == "setup_required"
    assert "需要先设置允许 IP" in model.title
    assert "设置" in model.details


def test_build_display_rows_puts_status_subtitle_and_details_in_button_safe_rows():
    app, _ = load_modules()
    model = app.StatusModel(
        state="safe",
        title="🟢 SAFE - 可以打开 Claude",
        details="static IP verified\nIP: 203.0.113.10",
        color="#0a7f3f",
    )

    rows = app.build_display_rows(model, "要求出口: 203.0.113.10 / US")

    assert rows == [
        ("title", "🟢 SAFE - 可以打开 Claude", "#0a7f3f"),
        ("subtitle", "要求出口: 203.0.113.10 / US", "#374151"),
        ("detail", "static IP verified", "#111827"),
        ("detail", "IP: 203.0.113.10", "#111827"),
        (
            "hint",
            "只有检测结果显示 SAFE，才打开 Claude Code；如果 ERROR 或 UNSAFE，宁可断开也不要换出口。",
            "#6b7280",
        ),
    ]


def test_app_uses_hardcoded_guard_defaults(tmp_path):
    app, guard = load_modules()

    assert guard.DEFAULT_PROXY == "http://127.0.0.1:7897"
    assert guard.DEFAULT_EXPECTED_IP == ""
    assert guard.DEFAULT_EXPECTED_COUNTRY == "US"


def test_load_settings_merges_saved_values_with_defaults(tmp_path):
    app, _ = load_modules()
    config_path = tmp_path / "settings.json"
    config_path.write_text(
        '{"proxy": "http://127.0.0.1:7890", "expected_ip": "1.2.3.4", "https_check": false}',
        encoding="utf-8",
    )

    settings = app.load_settings(config_path)

    assert settings.proxy == "http://127.0.0.1:7890"
    assert settings.expected_ip == "1.2.3.4"
    assert settings.expected_ips == "1.2.3.4"
    assert settings.expected_country == "US"
    assert settings.timeout == 10.0
    assert settings.retries == 1
    assert settings.https_check is False
    assert settings.claude_trace_check is True


def test_save_settings_round_trips_user_config(tmp_path):
    app, _ = load_modules()
    config_path = tmp_path / "settings.json"
    settings = app.AppSettings(
        proxy="http://127.0.0.1:7890",
        expected_ips="1.2.3.4\n5.6.7.8",
        expected_country="JP",
        timeout=5.5,
        retries=3,
        https_check=False,
        claude_trace_check=False,
    )

    app.save_settings(settings, config_path)

    assert app.load_settings(config_path) == settings


def test_build_subtitle_reflects_saved_settings():
    app, _ = load_modules()
    settings = app.AppSettings(
        proxy="http://127.0.0.1:7890",
        expected_ips="1.2.3.4\n5.6.7.8",
        expected_country="JP",
        timeout=5.5,
        retries=3,
        https_check=False,
        claude_trace_check=False,
    )

    subtitle = app.build_subtitle(settings)

    assert subtitle == "默认 IP: 1.2.3.4 / JP    允许 2 个 IP    代理: http://127.0.0.1:7890"


def test_default_expected_ip_uses_first_configured_ip():
    app, _ = load_modules()
    settings = app.AppSettings(
        proxy="http://127.0.0.1:7890",
        expected_ips="1.2.3.4\n5.6.7.8",
        expected_country="JP",
        timeout=5.5,
        retries=3,
        https_check=False,
        claude_trace_check=False,
    )

    assert settings.expected_ip == "1.2.3.4"
    assert app.format_expected_ips("1.2.3.4\n5.6.7.8") == ["1.2.3.4", "5.6.7.8"]


def test_app_declares_window_icon_resource():
    app, _ = load_modules()

    assert app.ICON_FILE_NAME == "claude-ip-guard.png"
