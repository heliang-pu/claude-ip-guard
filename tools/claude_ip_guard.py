#!/usr/bin/env python3
"""Guard Claude usage behind a fixed egress IP check.

This tool is intentionally strict: if it cannot prove the current proxy exits
through the expected static IP, it exits non-zero.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import NamedTuple


DEFAULT_PROXY = os.environ.get("CLAUDE_IP_GUARD_PROXY", "http://127.0.0.1:7897")
DEFAULT_EXPECTED_IP = os.environ.get("CLAUDE_IP_GUARD_IP", "").strip()
DEFAULT_EXPECTED_COUNTRY = os.environ.get("CLAUDE_IP_GUARD_COUNTRY", "US")
IP_API_URL = (
    "http://ip-api.com/json"
    "?fields=status,message,query,country,countryCode,regionName,city,isp,org,as"
)
HTTPS_IP_URL = "https://ifconfig.me/ip"
CLAUDE_TRACE_URL = "https://claude.ai/cdn-cgi/trace"
IP_RISK_URL_TEMPLATE = "https://ip.net.coffee/api/iprisk/{ip}"

EXIT_SAFE = 0
EXIT_UNSAFE = 1
EXIT_ERROR = 2


class IpCheckResult(NamedTuple):
    ip: str
    country_code: str
    country: str
    region: str
    city: str
    isp: str
    org: str
    source: str


class CloudflareTrace(NamedTuple):
    ip: str
    country_code: str
    source: str


class IpRiskResult(NamedTuple):
    ip: str
    trust_score: int | None
    ip_type_label: str
    company_type: str
    asn: int | None
    as_organization: str
    is_vpn: bool | None
    is_proxy: bool | None
    is_tor: bool | None
    is_crawler: bool | None
    is_abuser: bool | None


class Decision(NamedTuple):
    safe: bool
    exit_code: int
    reason: str


def normalize_expected_ips(expected_ip: str) -> list[str]:
    return [
        part.strip()
        for part in expected_ip.replace("\n", ",").split(",")
        if part.strip()
    ]


def require_expected_ips(expected_ip: str) -> list[str]:
    expected_ips = normalize_expected_ips(expected_ip)
    if not expected_ips:
        raise RuntimeError("expected IP is not configured")
    return expected_ips


def expected_ip_label(expected_ips: list[str]) -> str:
    if len(expected_ips) == 1:
        return expected_ips[0]
    return f"one of {', '.join(expected_ips)}"


def parse_ip_api_json(payload: bytes) -> IpCheckResult:
    data = json.loads(payload.decode("utf-8"))
    status = data.get("status")
    if status and status != "success":
        message = data.get("message") or "unknown ip-api error"
        raise RuntimeError(f"ip-api returned {status}: {message}")

    ip = str(data.get("query") or "").strip()
    country_code = str(data.get("countryCode") or "").strip().upper()
    if not ip or not country_code:
        raise RuntimeError("ip-api response is missing query or countryCode")

    return IpCheckResult(
        ip=ip,
        country_code=country_code,
        country=str(data.get("country") or "").strip(),
        region=str(data.get("regionName") or "").strip(),
        city=str(data.get("city") or "").strip(),
        isp=str(data.get("isp") or "").strip(),
        org=str(data.get("org") or "").strip(),
        source="ip-api",
    )


def parse_cloudflare_trace(payload: bytes, *, source: str = "claude.ai/cdn-cgi/trace") -> CloudflareTrace:
    lines = payload.decode("utf-8", errors="replace").splitlines()
    data = {}
    for line in lines:
        if "=" in line:
            key, value = line.split("=", 1)
            data[key.strip()] = value.strip()
    ip = data.get("ip", "")
    country_code = data.get("loc", "").upper()
    if not ip:
        raise RuntimeError(f"{source} response is missing ip")
    return CloudflareTrace(ip=ip, country_code=country_code, source=source)


def _optional_bool(data: dict, key: str) -> bool | None:
    value = data.get(key)
    return value if isinstance(value, bool) else None


def _optional_int(data: dict, key: str) -> int | None:
    value = data.get(key)
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_ip_risk_json(payload: bytes) -> IpRiskResult:
    data = json.loads(payload.decode("utf-8"))
    ip = str(data.get("ip") or "").strip()
    if not ip:
        raise RuntimeError("IP risk response is missing ip")

    is_residential = data.get("isResidential")
    if is_residential is True:
        ip_type_label = "家庭住宅IP"
    elif is_residential is False or data.get("is_datacenter") is True:
        ip_type_label = "机房IP"
    else:
        ip_type_label = "未知"

    return IpRiskResult(
        ip=ip,
        trust_score=_optional_int(data, "trust_score"),
        ip_type_label=ip_type_label,
        company_type=str(data.get("company_type") or "").strip(),
        asn=_optional_int(data, "asn"),
        as_organization=str(data.get("asOrganization") or data.get("company_name") or "").strip(),
        is_vpn=_optional_bool(data, "is_vpn"),
        is_proxy=_optional_bool(data, "is_proxy"),
        is_tor=_optional_bool(data, "is_tor"),
        is_crawler=_optional_bool(data, "is_crawler"),
        is_abuser=_optional_bool(data, "is_abuser"),
    )


def evaluate_result(
    result: IpCheckResult,
    *,
    expected_ip: str,
    expected_country: str,
) -> Decision:
    expected_ips = require_expected_ips(expected_ip)
    expected_country = expected_country.strip().upper()
    if expected_ips and result.ip not in expected_ips:
        return Decision(
            safe=False,
            exit_code=EXIT_UNSAFE,
            reason=f"expected IP {expected_ip_label(expected_ips)}, got {result.ip}",
        )
    if result.country_code != expected_country:
        return Decision(
            safe=False,
            exit_code=EXIT_UNSAFE,
            reason=f"expected country {expected_country}, got {result.country_code}",
        )
    return Decision(safe=True, exit_code=EXIT_SAFE, reason="Claude egress IP verified")


def evaluate_trace(
    trace: CloudflareTrace,
    *,
    expected_ip: str,
    expected_country: str,
) -> Decision:
    expected_ips = require_expected_ips(expected_ip)
    expected_country = expected_country.strip().upper()
    if expected_ips and trace.ip not in expected_ips:
        return Decision(
            safe=False,
            exit_code=EXIT_UNSAFE,
            reason=f"Claude AI expected IP {expected_ip_label(expected_ips)}, got {trace.ip}",
        )
    if expected_country and trace.country_code and trace.country_code != expected_country:
        return Decision(
            safe=False,
            exit_code=EXIT_UNSAFE,
            reason=f"Claude AI expected country {expected_country}, got {trace.country_code}",
        )
    return Decision(safe=True, exit_code=EXIT_SAFE, reason="Claude egress IP verified")


def fetch(url: str, *, proxy: str, timeout: float) -> bytes:
    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
    else:
        opener = urllib.request.build_opener()
    request = urllib.request.Request(url, headers={"User-Agent": "claude-ip-guard/1.0"})
    with opener.open(request, timeout=timeout) as response:
        return response.read()


def fetch_with_retries(url: str, *, proxy: str, timeout: float, retries: int) -> bytes:
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return fetch(url, proxy=proxy, timeout=timeout)
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(0.4)
    raise RuntimeError(str(last_error) if last_error else "request failed")


def parse_plain_ip(payload: bytes) -> str:
    return payload.decode("utf-8", errors="replace").strip().splitlines()[0].strip()


def fetch_ip_risk(ip: str, *, timeout: float, retries: int) -> IpRiskResult:
    payload = fetch_with_retries(
        IP_RISK_URL_TEMPLATE.format(ip=ip),
        proxy="",
        timeout=timeout,
        retries=retries,
    )
    return parse_ip_risk_json(payload)


def check_proxy(
    *,
    proxy: str,
    expected_ip: str,
    expected_country: str,
    timeout: float,
    retries: int,
    https_check: bool,
    claude_trace_check: bool = True,
) -> tuple[Decision, IpCheckResult | None, str | None, CloudflareTrace | None, IpRiskResult | None]:
    result = parse_ip_api_json(
        fetch_with_retries(IP_API_URL, proxy=proxy, timeout=timeout, retries=retries)
    )
    claude_trace = None
    if claude_trace_check:
        claude_trace = parse_cloudflare_trace(
            fetch_with_retries(CLAUDE_TRACE_URL, proxy=proxy, timeout=timeout, retries=retries)
        )
        decision = evaluate_trace(
            claude_trace,
            expected_ip=expected_ip,
            expected_country=expected_country,
        )
    else:
        decision = evaluate_result(
            result,
            expected_ip=expected_ip,
            expected_country=expected_country,
        )
    if not decision.safe:
        return decision, result, None, claude_trace, None

    https_ip = None
    if https_check:
        https_ip = parse_plain_ip(
            fetch_with_retries(HTTPS_IP_URL, proxy=proxy, timeout=timeout, retries=retries)
        )
        expected_ips = require_expected_ips(expected_ip)
        if https_ip not in expected_ips:
            return (
                Decision(
                    safe=False,
                    exit_code=EXIT_UNSAFE,
                    reason=f"HTTPS check expected IP {expected_ip_label(expected_ips)}, got {https_ip}",
                ),
                result,
                https_ip,
                claude_trace,
                None,
            )

    risk_ip = claude_trace.ip if claude_trace else result.ip
    risk = None
    try:
        risk = fetch_ip_risk(risk_ip, timeout=timeout, retries=retries)
    except Exception:
        risk = None

    return decision, result, https_ip, claude_trace, risk


def format_result(
    decision: Decision,
    result: IpCheckResult | None,
    *,
    proxy: str,
    https_ip: str | None,
    claude_trace: CloudflareTrace | None = None,
    risk: IpRiskResult | None = None,
) -> str:
    status = "SAFE" if decision.safe else "UNSAFE"
    lines = [f"{status}: {decision.reason}", f"Proxy: {proxy}"]
    if claude_trace:
        lines.append(f"Claude AI IP: {claude_trace.ip} ({claude_trace.country_code or 'unknown'})")
    if result:
        lines.extend(
            [
                f"Default IP: {result.ip}",
                f"Country: {result.country} ({result.country_code})",
                f"Location: {result.region} / {result.city}",
                f"ISP: {result.isp}",
                f"Org: {result.org}",
            ]
        )
    if https_ip:
        lines.append(f"HTTPS IP: {https_ip}")
    if risk:
        lines.extend(format_risk_lines(risk))
    return "\n".join(lines)


def yes_no(value: bool | None) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def format_risk_lines(risk: IpRiskResult) -> list[str]:
    type_text = risk.ip_type_label
    if risk.company_type:
        type_text = f"{type_text} ({risk.company_type})"
    lines = [
        f"Trust Score: {risk.trust_score if risk.trust_score is not None else 'unknown'}",
        f"IP Type: {type_text}",
    ]
    if risk.asn:
        lines.append(f"ASN: AS{risk.asn}")
    if risk.as_organization:
        lines.append(f"ASN Org: {risk.as_organization}")
    lines.extend(
        [
            f"VPN: {yes_no(risk.is_vpn)}",
            f"Proxy: {yes_no(risk.is_proxy)}",
            f"Tor: {yes_no(risk.is_tor)}",
            f"Crawler: {yes_no(risk.is_crawler)}",
            f"Abuse: {yes_no(risk.is_abuser)}",
        ]
    )
    return lines


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check that the current proxy exits through the fixed Claude-safe IP."
    )
    parser.add_argument("--proxy", default=DEFAULT_PROXY, help=f"default: {DEFAULT_PROXY}")
    parser.add_argument(
        "--expected-ip",
        default=DEFAULT_EXPECTED_IP,
        help=f"default: {DEFAULT_EXPECTED_IP}",
    )
    parser.add_argument(
        "--expected-country",
        default=DEFAULT_EXPECTED_COUNTRY,
        help=f"default: {DEFAULT_EXPECTED_COUNTRY}",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="request timeout seconds")
    parser.add_argument("--retries", type=int, default=1, help="retry count after failures")
    parser.add_argument(
        "--skip-https-check",
        action="store_true",
        help="only check ip-api HTTP identity; not recommended before Claude",
    )
    parser.add_argument(
        "--skip-claude-trace",
        action="store_true",
        help="skip claude.ai/cdn-cgi/trace egress verification; not recommended before Claude",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="optional command to exec after a safe check, e.g. -- claude",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    command = args.command
    if command and command[0] == "--":
        command = command[1:]

    try:
        decision, result, https_ip, claude_trace, risk = check_proxy(
            proxy=args.proxy,
            expected_ip=args.expected_ip,
            expected_country=args.expected_country,
            timeout=args.timeout,
            retries=args.retries,
            https_check=not args.skip_https_check,
            claude_trace_check=not args.skip_claude_trace,
        )
    except Exception as exc:
        print(f"ERROR: cannot verify static IP: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(
        format_result(
            decision,
            result,
            proxy=args.proxy,
            https_ip=https_ip,
            claude_trace=claude_trace,
            risk=risk,
        )
    )
    if not decision.safe:
        return decision.exit_code

    if command:
        os.execvp(command[0], command)
    return EXIT_SAFE


if __name__ == "__main__":
    raise SystemExit(main())
