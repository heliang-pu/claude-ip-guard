import Foundation

#if SWIFT_PACKAGE
import ClaudeIPGuardCore
#endif

struct SettingsStore {
    private let defaults: UserDefaults
    private let key = "claude-ip-guard.settings"

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    func load() -> GuardSettings {
        guard
            let data = defaults.data(forKey: key),
            let decoded = try? JSONDecoder().decode(GuardSettings.self, from: data)
        else {
            return GuardSettings()
        }
        let proxy = decoded.proxy == GuardSettings.legacyLocalProxy ? "" : decoded.proxy
        return GuardSettings(
            proxy: proxy,
            allowedIPsText: decoded.allowedIPsText,
            expectedCountry: decoded.expectedCountry,
            timeout: decoded.timeout,
            retries: decoded.retries,
            httpsCheckEnabled: decoded.httpsCheckEnabled,
            claudeTraceCheckEnabled: decoded.claudeTraceCheckEnabled
        )
    }

    func save(_ settings: GuardSettings) {
        if let data = try? JSONEncoder().encode(settings) {
            defaults.set(data, forKey: key)
        }
    }
}
