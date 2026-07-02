import Foundation

public enum GuardEvaluator {
    public static let exitSafe = 0
    public static let exitUnsafe = 1

    public static func evaluate(
        defaultIdentity: IPIdentity,
        claudeTrace: CloudflareTrace?,
        httpsIP: String?,
        risk: IPRisk?,
        settings: GuardSettings
    ) throws -> GuardReport {
        let allowedIPs = try requireAllowedIPs(settings.allowedIPs)
        let decision: GuardDecision

        if settings.claudeTraceCheckEnabled {
            guard let claudeTrace else {
                throw GuardError.missingClaudeTrace
            }
            decision = evaluateTrace(
                claudeTrace,
                allowedIPs: allowedIPs,
                expectedCountry: settings.expectedCountry
            )
        } else {
            decision = evaluateDefaultIdentity(
                defaultIdentity,
                allowedIPs: allowedIPs,
                expectedCountry: settings.expectedCountry
            )
        }

        if !decision.isSafe {
            return buildReport(
                decision: decision,
                defaultIdentity: defaultIdentity,
                claudeTrace: claudeTrace,
                httpsIP: nil,
                risk: nil
            )
        }

        if settings.httpsCheckEnabled {
            guard let httpsIP, !httpsIP.trimmed.isEmpty else {
                throw GuardError.missingHTTPSIP
            }
            if !allowedIPs.contains(httpsIP.trimmed) {
                let unsafe = GuardDecision(
                    isSafe: false,
                    exitCode: exitUnsafe,
                    reason: "HTTPS check expected IP \(expectedIPLabel(allowedIPs)), got \(httpsIP.trimmed)"
                )
                return buildReport(
                    decision: unsafe,
                    defaultIdentity: defaultIdentity,
                    claudeTrace: claudeTrace,
                    httpsIP: httpsIP.trimmed,
                    risk: nil
                )
            }
        }

        return buildReport(
            decision: decision,
            defaultIdentity: defaultIdentity,
            claudeTrace: claudeTrace,
            httpsIP: httpsIP?.trimmed,
            risk: risk
        )
    }

    public static func errorReport(_ message: String) -> GuardReport {
        GuardReport(
            decision: GuardDecision(isSafe: false, exitCode: 2, reason: message),
            status: .error(),
            detailLines: [message]
        )
    }

    public static func riskLines(_ risk: IPRisk) -> [String] {
        var typeText = risk.ipTypeLabel
        if !risk.companyType.isEmpty {
            typeText += " (\(risk.companyType))"
        }

        var lines = [
            "Trust Score: \(risk.trustScore.map(String.init) ?? "unknown")",
            "IP Type: \(typeText)",
        ]
        if let asn = risk.asn {
            lines.append("ASN: AS\(asn)")
        }
        if !risk.asOrganization.isEmpty {
            lines.append("ASN Org: \(risk.asOrganization)")
        }
        lines.append("VPN: \(yesNo(risk.isVPN))")
        lines.append("Proxy: \(yesNo(risk.isProxy))")
        lines.append("Tor: \(yesNo(risk.isTor))")
        lines.append("Crawler: \(yesNo(risk.isCrawler))")
        lines.append("Abuse: \(yesNo(risk.isAbuser))")
        return lines
    }

    static func evaluateDefaultIdentity(
        _ identity: IPIdentity,
        allowedIPs: [String],
        expectedCountry: String
    ) -> GuardDecision {
        if !allowedIPs.contains(identity.ip) {
            return GuardDecision(
                isSafe: false,
                exitCode: exitUnsafe,
                reason: "expected IP \(expectedIPLabel(allowedIPs)), got \(identity.ip)"
            )
        }
        if identity.countryCode != expectedCountry {
            return GuardDecision(
                isSafe: false,
                exitCode: exitUnsafe,
                reason: "expected country \(expectedCountry), got \(identity.countryCode)"
            )
        }
        return GuardDecision(isSafe: true, exitCode: exitSafe, reason: "Claude egress IP verified")
    }

    static func evaluateTrace(
        _ trace: CloudflareTrace,
        allowedIPs: [String],
        expectedCountry: String
    ) -> GuardDecision {
        if !allowedIPs.contains(trace.ip) {
            return GuardDecision(
                isSafe: false,
                exitCode: exitUnsafe,
                reason: "Claude AI expected IP \(expectedIPLabel(allowedIPs)), got \(trace.ip)"
            )
        }
        if !expectedCountry.isEmpty, !trace.countryCode.isEmpty, trace.countryCode != expectedCountry {
            return GuardDecision(
                isSafe: false,
                exitCode: exitUnsafe,
                reason: "Claude AI expected country \(expectedCountry), got \(trace.countryCode)"
            )
        }
        return GuardDecision(isSafe: true, exitCode: exitSafe, reason: "Claude egress IP verified")
    }

    static func buildReport(
        decision: GuardDecision,
        defaultIdentity: IPIdentity,
        claudeTrace: CloudflareTrace?,
        httpsIP: String?,
        risk: IPRisk?
    ) -> GuardReport {
        var details = [
            decision.reason,
            "Default IP: \(defaultIdentity.ip)",
        ]
        if let claudeTrace {
            let country = claudeTrace.countryCode.isEmpty ? "unknown" : claudeTrace.countryCode
            details.append("Claude AI IP: \(claudeTrace.ip) (\(country))")
        }
        details.append("Country: \(defaultIdentity.country) (\(defaultIdentity.countryCode))")
        details.append("Location: \(defaultIdentity.region) / \(defaultIdentity.city)")
        details.append("ISP: \(defaultIdentity.isp)")
        details.append("Org: \(defaultIdentity.org)")
        if let httpsIP, !httpsIP.isEmpty {
            details.append("HTTPS IP: \(httpsIP)")
        }
        if let risk {
            details.append(contentsOf: riskLines(risk))
        }

        let status = decision.isSafe
            ? GuardStatus(state: .safe, title: "SAFE - 可以打开 Claude", colorHex: "#0a7f3f")
            : GuardStatus(state: .unsafe, title: "UNSAFE - 不要打开 Claude", colorHex: "#b42318")

        return GuardReport(decision: decision, status: status, detailLines: details)
    }

    static func requireAllowedIPs(_ allowedIPs: [String]) throws -> [String] {
        if allowedIPs.isEmpty {
            throw GuardError.expectedIPMissing
        }
        return allowedIPs
    }

    static func expectedIPLabel(_ allowedIPs: [String]) -> String {
        allowedIPs.count == 1 ? allowedIPs[0] : "one of \(allowedIPs.joined(separator: ", "))"
    }

    static func yesNo(_ value: Bool?) -> String {
        switch value {
        case true:
            return "yes"
        case false:
            return "no"
        case nil:
            return "unknown"
        }
    }
}
