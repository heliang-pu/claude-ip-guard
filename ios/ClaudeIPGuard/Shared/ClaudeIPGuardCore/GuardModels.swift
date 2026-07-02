import Foundation

public enum GuardError: Error, Equatable, CustomStringConvertible {
    case expectedIPMissing
    case missingField(String)
    case invalidIPAPIStatus(String)
    case invalidJSON(String)
    case missingClaudeTrace
    case missingHTTPSIP
    case invalidProxy(String)
    case invalidURL(String)
    case requestFailed(String)

    public var description: String {
        switch self {
        case .expectedIPMissing:
            return "expected IP is not configured"
        case let .missingField(field):
            return "response is missing \(field)"
        case let .invalidIPAPIStatus(message):
            return message
        case let .invalidJSON(message):
            return message
        case .missingClaudeTrace:
            return "Claude trace result is missing"
        case .missingHTTPSIP:
            return "HTTPS IP result is missing"
        case let .invalidProxy(proxy):
            return "invalid proxy: \(proxy)"
        case let .invalidURL(url):
            return "invalid URL: \(url)"
        case let .requestFailed(message):
            return message
        }
    }
}

public struct GuardSettings: Codable, Equatable, Sendable {
    public static let defaultAllowedIPsText = "38.15.0.237"
    public static let legacyLocalProxy = "http://127.0.0.1:7897"

    public var proxy: String
    public var allowedIPsText: String
    public var expectedCountry: String
    public var timeout: TimeInterval
    public var retries: Int
    public var httpsCheckEnabled: Bool
    public var claudeTraceCheckEnabled: Bool

    public init(
        proxy: String = "",
        allowedIPsText: String = Self.defaultAllowedIPsText,
        expectedCountry: String = "US",
        timeout: TimeInterval = 10,
        retries: Int = 1,
        httpsCheckEnabled: Bool = true,
        claudeTraceCheckEnabled: Bool = true
    ) {
        self.proxy = proxy.trimmed
        self.allowedIPsText = allowedIPsText
        self.expectedCountry = expectedCountry.trimmed.uppercased()
        self.timeout = timeout
        self.retries = max(0, retries)
        self.httpsCheckEnabled = httpsCheckEnabled
        self.claudeTraceCheckEnabled = claudeTraceCheckEnabled
    }

    public var allowedIPs: [String] {
        Self.normalizeAllowedIPs(allowedIPsText)
    }

    public var defaultIP: String {
        allowedIPs.first ?? ""
    }

    public var hasAllowedIP: Bool {
        !allowedIPs.isEmpty
    }

    public var subtitle: String {
        let defaultIP = defaultIP.isEmpty ? "未设置" : defaultIP
        let proxyLabel = proxy.isEmpty ? "手机当前网络" : proxy
        return "默认 IP: \(defaultIP) / \(expectedCountry)    允许 \(allowedIPs.count) 个 IP    代理: \(proxyLabel)"
    }

    public static func normalizeAllowedIPs(_ value: String) -> [String] {
        value
            .replacingOccurrences(of: "\n", with: ",")
            .split(separator: ",")
            .map { String($0).trimmed }
            .filter { !$0.isEmpty }
    }
}

public struct IPIdentity: Equatable, Sendable {
    public let ip: String
    public let countryCode: String
    public let country: String
    public let region: String
    public let city: String
    public let isp: String
    public let org: String
    public let source: String

    public init(
        ip: String,
        countryCode: String,
        country: String,
        region: String,
        city: String,
        isp: String,
        org: String,
        source: String
    ) {
        self.ip = ip.trimmed
        self.countryCode = countryCode.trimmed.uppercased()
        self.country = country.trimmed
        self.region = region.trimmed
        self.city = city.trimmed
        self.isp = isp.trimmed
        self.org = org.trimmed
        self.source = source.trimmed
    }

    public init(ipAPIData data: Data) throws {
        let response: IPAPIResponse
        do {
            response = try JSONDecoder().decode(IPAPIResponse.self, from: data)
        } catch {
            throw GuardError.invalidJSON(error.localizedDescription)
        }

        if let status = response.status?.trimmed, !status.isEmpty, status != "success" {
            let message = response.message?.trimmed ?? "unknown ip-api error"
            throw GuardError.invalidIPAPIStatus("ip-api returned \(status): \(message)")
        }

        let ip = response.query?.trimmed ?? ""
        let countryCode = response.countryCode?.trimmed.uppercased() ?? ""
        if ip.isEmpty {
            throw GuardError.missingField("query")
        }
        if countryCode.isEmpty {
            throw GuardError.missingField("countryCode")
        }

        self.init(
            ip: ip,
            countryCode: countryCode,
            country: response.country ?? "",
            region: response.regionName ?? "",
            city: response.city ?? "",
            isp: response.isp ?? "",
            org: response.org ?? "",
            source: "ip-api"
        )
    }
}

public struct CloudflareTrace: Equatable, Sendable {
    public let ip: String
    public let countryCode: String
    public let source: String

    public init(ip: String, countryCode: String, source: String) {
        self.ip = ip.trimmed
        self.countryCode = countryCode.trimmed.uppercased()
        self.source = source.trimmed
    }

    public init(traceData data: Data, source: String = "claude.ai/cdn-cgi/trace") throws {
        let text = String(decoding: data, as: UTF8.self)
        var values: [String: String] = [:]
        for line in text.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: "=", maxSplits: 1)
            if parts.count == 2 {
                values[String(parts[0]).trimmed] = String(parts[1]).trimmed
            }
        }

        let ip = values["ip"] ?? ""
        if ip.isEmpty {
            throw GuardError.missingField("ip")
        }
        self.init(ip: ip, countryCode: values["loc"] ?? "", source: source)
    }
}

public struct IPRisk: Equatable, Sendable {
    public let ip: String
    public let trustScore: Int?
    public let ipTypeLabel: String
    public let companyType: String
    public let asn: Int?
    public let asOrganization: String
    public let isVPN: Bool?
    public let isProxy: Bool?
    public let isTor: Bool?
    public let isCrawler: Bool?
    public let isAbuser: Bool?

    public init(
        ip: String,
        trustScore: Int?,
        ipTypeLabel: String,
        companyType: String,
        asn: Int?,
        asOrganization: String,
        isVPN: Bool?,
        isProxy: Bool?,
        isTor: Bool?,
        isCrawler: Bool?,
        isAbuser: Bool?
    ) {
        self.ip = ip.trimmed
        self.trustScore = trustScore
        self.ipTypeLabel = ipTypeLabel.trimmed
        self.companyType = companyType.trimmed
        self.asn = asn
        self.asOrganization = asOrganization.trimmed
        self.isVPN = isVPN
        self.isProxy = isProxy
        self.isTor = isTor
        self.isCrawler = isCrawler
        self.isAbuser = isAbuser
    }

    public init(ipRiskData data: Data) throws {
        let object: Any
        do {
            object = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw GuardError.invalidJSON(error.localizedDescription)
        }
        guard let values = object as? [String: Any] else {
            throw GuardError.invalidJSON("IP risk response is not an object")
        }

        let ip = stringValue(values["ip"])
        if ip.isEmpty {
            throw GuardError.missingField("ip")
        }

        let isResidential = optionalBool(values["isResidential"])
        let isDatacenter = optionalBool(values["is_datacenter"])
        let ipTypeLabel: String
        if isResidential == true {
            ipTypeLabel = "家庭住宅IP"
        } else if isResidential == false || isDatacenter == true {
            ipTypeLabel = "机房IP"
        } else {
            ipTypeLabel = "未知"
        }

        self.init(
            ip: ip,
            trustScore: optionalInt(values["trust_score"]),
            ipTypeLabel: ipTypeLabel,
            companyType: stringValue(values["company_type"]),
            asn: optionalInt(values["asn"]),
            asOrganization: stringValue(values["asOrganization"]).isEmpty
                ? stringValue(values["company_name"])
                : stringValue(values["asOrganization"]),
            isVPN: optionalBool(values["is_vpn"]),
            isProxy: optionalBool(values["is_proxy"]),
            isTor: optionalBool(values["is_tor"]),
            isCrawler: optionalBool(values["is_crawler"]),
            isAbuser: optionalBool(values["is_abuser"])
        )
    }
}

public struct GuardDecision: Equatable, Sendable {
    public let isSafe: Bool
    public let exitCode: Int
    public let reason: String

    public init(isSafe: Bool, exitCode: Int, reason: String) {
        self.isSafe = isSafe
        self.exitCode = exitCode
        self.reason = reason
    }
}

public enum GuardState: String, Equatable, Sendable {
    case checking
    case setupRequired
    case safe
    case unsafe
    case error
}

public struct GuardStatus: Equatable, Sendable {
    public let state: GuardState
    public let title: String
    public let colorHex: String

    public init(state: GuardState, title: String, colorHex: String) {
        self.state = state
        self.title = title
        self.colorHex = colorHex
    }

    public static let checking = GuardStatus(
        state: .checking,
        title: "正在检测出口 IP...",
        colorHex: "#1d4ed8"
    )

    public static let setupRequired = GuardStatus(
        state: .setupRequired,
        title: "需要先设置允许 IP",
        colorHex: "#b45309"
    )

    public static func error() -> GuardStatus {
        GuardStatus(state: .error, title: "ERROR - 无法验证，别打开 Claude", colorHex: "#b45309")
    }
}

public struct GuardReport: Equatable, Sendable {
    public let decision: GuardDecision
    public let status: GuardStatus
    public let detailLines: [String]

    public init(decision: GuardDecision, status: GuardStatus, detailLines: [String]) {
        self.decision = decision
        self.status = status
        self.detailLines = detailLines
    }
}

struct IPAPIResponse: Decodable {
    let status: String?
    let message: String?
    let query: String?
    let countryCode: String?
    let country: String?
    let regionName: String?
    let city: String?
    let isp: String?
    let org: String?
}

func stringValue(_ value: Any?) -> String {
    switch value {
    case let string as String:
        return string.trimmed
    case let number as NSNumber:
        return number.stringValue
    default:
        return ""
    }
}

func optionalBool(_ value: Any?) -> Bool? {
    value as? Bool
}

func optionalInt(_ value: Any?) -> Int? {
    if value is Bool {
        return nil
    }
    if let intValue = value as? Int {
        return intValue
    }
    if let number = value as? NSNumber {
        return number.intValue
    }
    if let string = value as? String {
        return Int(string.trimmed)
    }
    return nil
}

extension String {
    var trimmed: String {
        trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
