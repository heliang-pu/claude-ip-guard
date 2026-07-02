import Foundation
import ClaudeIPGuardCore

@main
struct ClaudeIPGuardCoreSmokeTests {
    static func main() throws {
        try run("IP API parser extracts identity", ipAPIParserExtractsIdentity)
        try run("Cloudflare trace parser extracts Claude IP and country", cloudflareTraceParserExtractsClaudeIPAndCountry)
        try run("IP risk parser extracts type and security flags", ipRiskParserExtractsTypeAndSecurityFlags)
        try run("Default settings hardcode the safe Claude egress IP", defaultSettingsHardcodeSafeClaudeEgressIP)
        try run("Settings normalize allowed IPs and build subtitle", settingsNormalizesAllowedIPsAndBuildsSubtitle)
        try run("Settings default to phone network when proxy is blank", settingsDefaultToPhoneNetworkWhenProxyIsBlank)
        try run("Evaluator builds safe status rows when all checks match", evaluatorBuildsSafeStatusRowsWhenAllChecksMatch)
        try run("Evaluator rejects wrong Claude trace IP", evaluatorRejectsWrongClaudeTraceIP)
        print("All ClaudeIPGuardCore smoke tests passed")
    }

    static func ipAPIParserExtractsIdentity() throws {
        let payload = Data("""
        {
          "status": "success",
          "query": "203.0.113.10",
          "countryCode": "US",
          "country": "United States",
          "regionName": "New Jersey",
          "city": "Hackensack",
          "isp": "Cogent Communications",
          "org": "Fiberpower LLC"
        }
        """.utf8)

        let identity = try IPIdentity(ipAPIData: payload)

        try expect(identity.ip == "203.0.113.10")
        try expect(identity.countryCode == "US")
        try expect(identity.country == "United States")
        try expect(identity.region == "New Jersey")
        try expect(identity.city == "Hackensack")
        try expect(identity.isp == "Cogent Communications")
        try expect(identity.org == "Fiberpower LLC")
    }

    static func cloudflareTraceParserExtractsClaudeIPAndCountry() throws {
        let payload = Data("fl=123f45\nh=claude.ai\nip=203.0.113.10\nts=1712345678.123\nloc=US\n".utf8)

        let trace = try CloudflareTrace(traceData: payload)

        try expect(trace.ip == "203.0.113.10")
        try expect(trace.countryCode == "US")
        try expect(trace.source == "claude.ai/cdn-cgi/trace")
    }

    static func ipRiskParserExtractsTypeAndSecurityFlags() throws {
        let payload = Data("""
        {
          "ip": "203.0.113.10",
          "is_datacenter": false,
          "isResidential": true,
          "is_vpn": false,
          "is_proxy": false,
          "is_tor": false,
          "is_crawler": false,
          "is_abuser": false,
          "company_type": "isp",
          "asn": 174,
          "asOrganization": "Cogent Communications, LLC",
          "trust_score": 90
        }
        """.utf8)

        let risk = try IPRisk(ipRiskData: payload)

        try expect(risk.ip == "203.0.113.10")
        try expect(risk.trustScore == 90)
        try expect(risk.ipTypeLabel == "家庭住宅IP")
        try expect(risk.companyType == "isp")
        try expect(risk.asn == 174)
        try expect(risk.asOrganization == "Cogent Communications, LLC")
        try expect(risk.isVPN == false)
        try expect(risk.isProxy == false)
        try expect(risk.isTor == false)
    }

    static func defaultSettingsHardcodeSafeClaudeEgressIP() throws {
        let settings = GuardSettings()

        try expect(settings.proxy == "")
        try expect(settings.allowedIPs == ["38.15.0.237"])
        try expect(settings.defaultIP == "38.15.0.237")
        try expect(settings.expectedCountry == "US")
        try expect(settings.subtitle == "默认 IP: 38.15.0.237 / US    允许 1 个 IP    代理: 手机当前网络")
    }

    static func settingsNormalizesAllowedIPsAndBuildsSubtitle() throws {
        let settings = GuardSettings(
            proxy: "http://127.0.0.1:7897",
            allowedIPsText: "203.0.113.10\n203.0.113.11, 203.0.113.12",
            expectedCountry: "us",
            timeout: 10,
            retries: 1,
            httpsCheckEnabled: true,
            claudeTraceCheckEnabled: true
        )

        try expect(settings.allowedIPs == ["203.0.113.10", "203.0.113.11", "203.0.113.12"])
        try expect(settings.defaultIP == "203.0.113.10")
        try expect(settings.expectedCountry == "US")
        try expect(settings.subtitle == "默认 IP: 203.0.113.10 / US    允许 3 个 IP    代理: http://127.0.0.1:7897")
    }

    static func settingsDefaultToPhoneNetworkWhenProxyIsBlank() throws {
        let settings = GuardSettings(
            allowedIPsText: "38.15.0.237",
            expectedCountry: "US",
            timeout: 10,
            retries: 1,
            httpsCheckEnabled: true,
            claudeTraceCheckEnabled: true
        )

        try expect(settings.proxy == "")
        try expect(settings.subtitle == "默认 IP: 38.15.0.237 / US    允许 1 个 IP    代理: 手机当前网络")
    }

    static func evaluatorBuildsSafeStatusRowsWhenAllChecksMatch() throws {
        let settings = GuardSettings(
            proxy: "http://127.0.0.1:7897",
            allowedIPsText: "203.0.113.10, 203.0.113.11",
            expectedCountry: "US",
            timeout: 10,
            retries: 1,
            httpsCheckEnabled: true,
            claudeTraceCheckEnabled: true
        )
        let identity = IPIdentity(
            ip: "203.0.113.11",
            countryCode: "US",
            country: "United States",
            region: "New Jersey",
            city: "Hackensack",
            isp: "Cogent Communications",
            org: "Fiberpower LLC",
            source: "ip-api"
        )
        let trace = CloudflareTrace(ip: "203.0.113.11", countryCode: "US", source: "claude.ai/cdn-cgi/trace")
        let risk = IPRisk(
            ip: "203.0.113.11",
            trustScore: 90,
            ipTypeLabel: "家庭住宅IP",
            companyType: "isp",
            asn: 174,
            asOrganization: "Cogent Communications, LLC",
            isVPN: false,
            isProxy: false,
            isTor: false,
            isCrawler: false,
            isAbuser: false
        )

        let report = try GuardEvaluator.evaluate(
            defaultIdentity: identity,
            claudeTrace: trace,
            httpsIP: "203.0.113.11",
            risk: risk,
            settings: settings
        )

        try expect(report.decision.isSafe)
        try expect(report.status.state == .safe)
        try expect(report.status.title == "SAFE - 可以打开 Claude")
        try expect(report.status.colorHex == "#0a7f3f")
        try expect(report.detailLines.contains("Claude egress IP verified"))
        try expect(report.detailLines.contains("Default IP: 203.0.113.11"))
        try expect(report.detailLines.contains("Claude AI IP: 203.0.113.11 (US)"))
        try expect(report.detailLines.contains("HTTPS IP: 203.0.113.11"))
        try expect(report.detailLines.contains("Trust Score: 90"))
        try expect(report.detailLines.contains("IP Type: 家庭住宅IP (isp)"))
        try expect(report.detailLines.contains("VPN: no"))
    }

    static func evaluatorRejectsWrongClaudeTraceIP() throws {
        let settings = GuardSettings(
            proxy: "http://127.0.0.1:7897",
            allowedIPsText: "203.0.113.10",
            expectedCountry: "US",
            timeout: 10,
            retries: 1,
            httpsCheckEnabled: true,
            claudeTraceCheckEnabled: true
        )
        let identity = IPIdentity(
            ip: "203.0.113.10",
            countryCode: "US",
            country: "United States",
            region: "New Jersey",
            city: "Hackensack",
            isp: "Cogent Communications",
            org: "Fiberpower LLC",
            source: "ip-api"
        )
        let trace = CloudflareTrace(ip: "216.227.169.92", countryCode: "US", source: "claude.ai/cdn-cgi/trace")

        let report = try GuardEvaluator.evaluate(
            defaultIdentity: identity,
            claudeTrace: trace,
            httpsIP: nil,
            risk: nil,
            settings: settings
        )

        try expect(!report.decision.isSafe)
        try expect(report.status.state == .unsafe)
        try expect(report.status.title == "UNSAFE - 不要打开 Claude")
        try expect(report.decision.reason == "Claude AI expected IP 203.0.113.10, got 216.227.169.92")
    }

    static func run(_ name: String, _ test: () throws -> Void) throws {
        do {
            try test()
            print("PASS: \(name)")
        } catch {
            print("FAIL: \(name)")
            throw error
        }
    }

    static func expect(_ condition: @autoclosure () -> Bool, _ message: String = "expectation failed") throws {
        if !condition() {
            throw SmokeTestFailure(message)
        }
    }
}

struct SmokeTestFailure: Error, CustomStringConvertible {
    let description: String

    init(_ description: String) {
        self.description = description
    }
}
