import CFNetwork
import Foundation

public struct ProxyEndpoint: Equatable, Sendable {
    public let scheme: String
    public let host: String
    public let port: Int

    public init?(urlString: String) {
        guard
            let url = URL(string: urlString.trimmed),
            let host = url.host,
            let port = url.port
        else {
            return nil
        }
        self.scheme = (url.scheme ?? "http").lowercased()
        self.host = host
        self.port = port
    }

    public var connectionProxyDictionary: [AnyHashable: Any] {
        [
            kCFNetworkProxiesHTTPEnable as String: true,
            kCFNetworkProxiesHTTPProxy as String: host,
            kCFNetworkProxiesHTTPPort as String: port,
            "HTTPSEnable": true,
            "HTTPSProxy": host,
            "HTTPSPort": port,
        ]
    }
}

public struct GuardEndpoints: Sendable {
    public var ipAPIURL: String
    public var httpsIPURL: String
    public var claudeTraceURL: String
    public var ipRiskURLTemplate: String

    public init(
        ipAPIURL: String = "http://ip-api.com/json?fields=status,message,query,country,countryCode,regionName,city,isp,org,as",
        httpsIPURL: String = "https://ifconfig.me/ip",
        claudeTraceURL: String = "https://claude.ai/cdn-cgi/trace",
        ipRiskURLTemplate: String = "https://ip.net.coffee/api/iprisk/{ip}"
    ) {
        self.ipAPIURL = ipAPIURL
        self.httpsIPURL = httpsIPURL
        self.claudeTraceURL = claudeTraceURL
        self.ipRiskURLTemplate = ipRiskURLTemplate
    }
}

public final class GuardNetworkService: @unchecked Sendable {
    public let endpoints: GuardEndpoints

    public init(endpoints: GuardEndpoints = GuardEndpoints()) {
        self.endpoints = endpoints
    }

    public func check(settings: GuardSettings) async throws -> GuardReport {
        let defaultIdentity = try IPIdentity(
            ipAPIData: try await fetchWithRetries(
                endpoints.ipAPIURL,
                proxy: settings.proxy,
                timeout: settings.timeout,
                retries: settings.retries
            )
        )

        let claudeTrace: CloudflareTrace?
        if settings.claudeTraceCheckEnabled {
            claudeTrace = try CloudflareTrace(
                traceData: try await fetchWithRetries(
                    endpoints.claudeTraceURL,
                    proxy: settings.proxy,
                    timeout: settings.timeout,
                    retries: settings.retries
                )
            )
        } else {
            claudeTrace = nil
        }

        let preHTTPSSettings = GuardSettings(
            proxy: settings.proxy,
            allowedIPsText: settings.allowedIPsText,
            expectedCountry: settings.expectedCountry,
            timeout: settings.timeout,
            retries: settings.retries,
            httpsCheckEnabled: false,
            claudeTraceCheckEnabled: settings.claudeTraceCheckEnabled
        )
        let preliminary = try GuardEvaluator.evaluate(
            defaultIdentity: defaultIdentity,
            claudeTrace: claudeTrace,
            httpsIP: nil,
            risk: nil,
            settings: preHTTPSSettings
        )

        guard preliminary.decision.isSafe else {
            return preliminary
        }

        let httpsIP: String?
        if settings.httpsCheckEnabled {
            httpsIP = parsePlainIP(
                try await fetchWithRetries(
                    endpoints.httpsIPURL,
                    proxy: settings.proxy,
                    timeout: settings.timeout,
                    retries: settings.retries
                )
            )
        } else {
            httpsIP = nil
        }

        let postHTTPS = try GuardEvaluator.evaluate(
            defaultIdentity: defaultIdentity,
            claudeTrace: claudeTrace,
            httpsIP: httpsIP,
            risk: nil,
            settings: settings
        )

        guard postHTTPS.decision.isSafe else {
            return postHTTPS
        }

        let riskIP = claudeTrace?.ip ?? defaultIdentity.ip
        let risk = try? await fetchRisk(ip: riskIP, timeout: settings.timeout, retries: settings.retries)
        return try GuardEvaluator.evaluate(
            defaultIdentity: defaultIdentity,
            claudeTrace: claudeTrace,
            httpsIP: httpsIP,
            risk: risk,
            settings: settings
        )
    }

    public func fetchRisk(ip: String, timeout: TimeInterval, retries: Int) async throws -> IPRisk {
        let url = endpoints.ipRiskURLTemplate.replacingOccurrences(of: "{ip}", with: ip)
        return try IPRisk(
            ipRiskData: try await fetchWithRetries(url, proxy: "", timeout: timeout, retries: retries)
        )
    }

    public func fetchWithRetries(
        _ urlString: String,
        proxy: String,
        timeout: TimeInterval,
        retries: Int
    ) async throws -> Data {
        var lastError: Error?
        for attempt in 0...max(0, retries) {
            do {
                return try await fetch(urlString, proxy: proxy, timeout: timeout)
            } catch {
                lastError = error
                if attempt < retries {
                    try await Task.sleep(nanoseconds: 400_000_000)
                }
            }
        }
        throw GuardError.requestFailed(lastError?.localizedDescription ?? "request failed")
    }

    public func parsePlainIP(_ data: Data) -> String {
        String(decoding: data, as: UTF8.self)
            .split(whereSeparator: \.isNewline)
            .first
            .map { String($0).trimmed } ?? ""
    }

    func fetch(_ urlString: String, proxy: String, timeout: TimeInterval) async throws -> Data {
        guard let url = URL(string: urlString) else {
            throw GuardError.invalidURL(urlString)
        }

        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout
        configuration.httpAdditionalHeaders = ["User-Agent": "claude-ip-guard-ios/1.0"]
        if !proxy.trimmed.isEmpty {
            guard let proxyEndpoint = ProxyEndpoint(urlString: proxy) else {
                throw GuardError.invalidProxy(proxy)
            }
            configuration.connectionProxyDictionary = proxyEndpoint.connectionProxyDictionary
        }

        let session = URLSession(configuration: configuration)
        defer { session.finishTasksAndInvalidate() }

        var request = URLRequest(url: url)
        request.timeoutInterval = timeout
        let (data, response) = try await session.data(for: request)
        if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw GuardError.requestFailed("HTTP \(http.statusCode) from \(url.host ?? urlString)")
        }
        return data
    }
}
