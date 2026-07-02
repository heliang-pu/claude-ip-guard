import SwiftUI

#if SWIFT_PACKAGE
import ClaudeIPGuardCore
#endif

struct SettingsView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var draft: SettingsDraft
    @State private var validationMessage = ""

    let onSave: (GuardSettings) -> Void

    init(settings: GuardSettings, onSave: @escaping (GuardSettings) -> Void) {
        _draft = State(initialValue: SettingsDraft(settings: settings))
        self.onSave = onSave
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("出口") {
                    TextEditor(text: $draft.allowedIPsText)
                        .font(.system(.body, design: .monospaced))
                        .frame(minHeight: 96)
                        .accessibilityLabel("允许 IP")

                    TextField("代理", text: $draft.proxy)
                        .autocorrectionDisabled()

                    Text("留空表示使用手机当前网络、蜂窝数据或系统 VPN。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)

                    TextField("国家代码", text: $draft.expectedCountry)
                        .autocorrectionDisabled()
                }

                Section("检测") {
                    TextField("超时秒数", text: $draft.timeout)
                    TextField("重试次数", text: $draft.retries)
                    Toggle("启用 HTTPS 二次校验", isOn: $draft.httpsCheckEnabled)
                    Toggle("使用 Claude AI 出口 IP 校验", isOn: $draft.claudeTraceCheckEnabled)
                }

                if !validationMessage.isEmpty {
                    Section {
                        Text(validationMessage)
                            .foregroundStyle(Color(hex: "#b42318"))
                    }
                }
            }
            .navigationTitle("设置")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button {
                        dismiss()
                    } label: {
                        Label("取消", systemImage: "xmark")
                    }
                }

                ToolbarItem(placement: .confirmationAction) {
                    Button {
                        save()
                    } label: {
                        Label("保存", systemImage: "checkmark")
                    }
                }
            }
        }
    }

    private func save() {
        switch draft.makeSettings() {
        case let .success(settings):
            onSave(settings)
            dismiss()
        case let .failure(message):
            validationMessage = message
        }
    }
}

struct SettingsDraft: Equatable {
    var proxy: String
    var allowedIPsText: String
    var expectedCountry: String
    var timeout: String
    var retries: String
    var httpsCheckEnabled: Bool
    var claudeTraceCheckEnabled: Bool

    init(settings: GuardSettings) {
        proxy = settings.proxy
        allowedIPsText = settings.allowedIPsText
        expectedCountry = settings.expectedCountry
        timeout = String(format: "%.1f", settings.timeout)
        retries = String(settings.retries)
        httpsCheckEnabled = settings.httpsCheckEnabled
        claudeTraceCheckEnabled = settings.claudeTraceCheckEnabled
    }

    func makeSettings() -> SettingsValidation {
        let normalizedIPs = GuardSettings.normalizeAllowedIPs(allowedIPsText)
        guard !normalizedIPs.isEmpty else {
            return .failure("允许 IP 不能为空。")
        }
        guard !expectedCountry.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return .failure("国家代码不能为空。")
        }
        guard let timeoutValue = Double(timeout), timeoutValue > 0 else {
            return .failure("超时秒数需要是大于 0 的数字。")
        }
        guard let retriesValue = Int(retries), retriesValue >= 0 else {
            return .failure("重试次数需要是非负整数。")
        }

        return .success(
            GuardSettings(
                proxy: proxy,
                allowedIPsText: normalizedIPs.joined(separator: "\n"),
                expectedCountry: expectedCountry,
                timeout: timeoutValue,
                retries: retriesValue,
                httpsCheckEnabled: httpsCheckEnabled,
                claudeTraceCheckEnabled: claudeTraceCheckEnabled
            )
        )
    }
}

enum SettingsValidation {
    case success(GuardSettings)
    case failure(String)
}
