import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "claude_ip_guard.py"


def load_module():
    spec = importlib.util.spec_from_file_location("claude_ip_guard", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_parse_ip_api_json_extracts_identity():
    guard = load_module()

    result = guard.parse_ip_api_json(
        b'{"status":"success","query":"203.0.113.10","countryCode":"US",'
        b'"country":"United States","regionName":"New Jersey","city":"Hackensack",'
        b'"isp":"Cogent Communications","org":"Fiberpower LLC"}'
    )

    assert result.ip == "203.0.113.10"
    assert result.country_code == "US"
    assert result.country == "United States"
    assert result.city == "Hackensack"


def test_decision_is_safe_only_for_expected_static_us_ip():
    guard = load_module()
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

    decision = guard.evaluate_result(result, expected_ip="203.0.113.10", expected_country="US")

    assert decision.safe is True
    assert decision.exit_code == guard.EXIT_SAFE


def test_decision_rejects_same_country_wrong_ip():
    guard = load_module()
    result = guard.IpCheckResult(
        ip="216.227.169.92",
        country_code="US",
        country="United States",
        region="California",
        city="Los Angeles",
        isp="FDCservers.net",
        org="FDCservers.net",
        source="ip-api",
    )

    decision = guard.evaluate_result(result, expected_ip="203.0.113.10", expected_country="US")

    assert decision.safe is False
    assert decision.exit_code == guard.EXIT_UNSAFE
    assert "expected IP 203.0.113.10" in decision.reason


def test_decision_requires_configured_expected_ip():
    guard = load_module()
    result = guard.IpCheckResult(
        ip="203.0.113.10",
        country_code="US",
        country="United States",
        region="New Jersey",
        city="Hackensack",
        isp="Example ISP",
        org="Example Org",
        source="ip-api",
    )

    try:
        guard.evaluate_result(result, expected_ip="", expected_country="US")
    except RuntimeError as exc:
        assert "expected IP is not configured" in str(exc)
    else:
        raise AssertionError("empty expected IP should not be accepted")


def test_decision_accepts_any_configured_expected_ip():
    guard = load_module()
    result = guard.IpCheckResult(
        ip="203.0.113.11",
        country_code="US",
        country="United States",
        region="New Jersey",
        city="Hackensack",
        isp="Cogent Communications",
        org="Fiberpower LLC",
        source="ip-api",
    )

    decision = guard.evaluate_result(
        result,
        expected_ip="203.0.113.10, 203.0.113.11",
        expected_country="US",
    )

    assert decision.safe is True
    assert decision.reason == "Claude egress IP verified"


def test_parse_cloudflare_trace_extracts_claude_ip_and_country():
    guard = load_module()

    trace = guard.parse_cloudflare_trace(
        b"fl=123f45\nh=claude.ai\nip=203.0.113.10\nts=1712345678.123\nloc=US\n"
    )

    assert trace.ip == "203.0.113.10"
    assert trace.country_code == "US"
    assert trace.source == "claude.ai/cdn-cgi/trace"


def test_parse_ip_risk_json_extracts_type_and_security_flags():
    guard = load_module()

    risk = guard.parse_ip_risk_json(
        b'{"ip":"203.0.113.10","is_datacenter":false,"isResidential":true,'
        b'"is_vpn":false,"is_proxy":false,"is_tor":false,"is_crawler":false,'
        b'"is_abuser":false,"company_type":"isp","asn":174,'
        b'"asOrganization":"Cogent Communications, LLC","trust_score":90}'
    )

    assert risk.ip == "203.0.113.10"
    assert risk.ip_type_label == "家庭住宅IP"
    assert risk.company_type == "isp"
    assert risk.trust_score == 90
    assert risk.asn == 174
    assert risk.is_vpn is False


def test_format_result_includes_claude_and_https_egress_ips():
    guard = load_module()
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
    claude_trace = guard.CloudflareTrace(
        ip="203.0.113.10",
        country_code="US",
        source="claude.ai/cdn-cgi/trace",
    )
    decision = guard.Decision(True, guard.EXIT_SAFE, "Claude egress IP verified")

    text = guard.format_result(
        decision,
        result,
        proxy="http://127.0.0.1:7897",
        https_ip="203.0.113.10",
        claude_trace=claude_trace,
        risk=guard.IpRiskResult(
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
        ),
    )

    assert "Default IP: 203.0.113.10" in text
    assert "Claude AI IP: 203.0.113.10 (US)" in text
    assert "HTTPS IP: 203.0.113.10" in text
    assert "Trust Score: 90" in text
    assert "IP Type: 家庭住宅IP (isp)" in text
    assert "VPN: no" in text


def test_decision_rejects_expected_ip_in_wrong_country():
    guard = load_module()
    result = guard.IpCheckResult(
        ip="203.0.113.10",
        country_code="JP",
        country="Japan",
        region="Tokyo",
        city="Tokyo",
        isp="Example",
        org="Example",
        source="ip-api",
    )

    decision = guard.evaluate_result(result, expected_ip="203.0.113.10", expected_country="US")

    assert decision.safe is False
    assert decision.exit_code == guard.EXIT_UNSAFE
    assert "expected country US" in decision.reason
