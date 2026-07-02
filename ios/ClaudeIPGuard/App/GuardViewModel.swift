import Foundation
import SwiftUI

#if SWIFT_PACKAGE
import ClaudeIPGuardCore
#endif

@MainActor
final class GuardViewModel: ObservableObject {
    @Published private(set) var settings: GuardSettings
    @Published private(set) var status: GuardStatus
    @Published private(set) var detailLines: [String]
    @Published private(set) var isChecking = false
    @Published var isShowingSettings = false

    private let service: GuardNetworkService
    private let settingsStore: SettingsStore

    init(
        service: GuardNetworkService = GuardNetworkService(),
        settingsStore: SettingsStore = SettingsStore()
    ) {
        self.service = service
        self.settingsStore = settingsStore
        let loadedSettings = settingsStore.load()
        settings = loadedSettings
        if loadedSettings.hasAllowedIP {
            status = .checking
            detailLines = ["请稍等。检测通过前不要打开 Claude Code。"]
        } else {
            status = .setupRequired
            detailLines = ["点击设置，填写你的 Claude 出口 IP。第一行会作为默认 IP。"]
        }
    }

    var displayRows: [DisplayRow] {
        var rows = [
            DisplayRow(id: "title", kind: .title, text: status.title, colorHex: status.colorHex),
            DisplayRow(id: "subtitle", kind: .subtitle, text: settings.subtitle, colorHex: "#374151"),
        ]
        rows.append(
            contentsOf: detailLines.enumerated().map { index, line in
                DisplayRow(id: "detail-\(index)-\(line)", kind: .detail, text: line, colorHex: "#111827")
            }
        )
        return rows
    }

    func checkOnAppear() {
        guard status.state == .checking, settings.hasAllowedIP, !isChecking else {
            return
        }
        runCheck()
    }

    func runCheck() {
        guard settings.hasAllowedIP else {
            status = .setupRequired
            detailLines = ["点击设置，填写你的 Claude 出口 IP。第一行会作为默认 IP。"]
            return
        }

        status = .checking
        detailLines = ["请稍等。检测通过前不要打开 Claude Code。"]
        isChecking = true

        let currentSettings = settings
        Task {
            do {
                let report = try await service.check(settings: currentSettings)
                apply(report)
            } catch {
                apply(GuardEvaluator.errorReport(errorDescription(error)))
            }
            isChecking = false
        }
    }

    func applySettings(_ updatedSettings: GuardSettings) {
        settings = updatedSettings
        settingsStore.save(updatedSettings)
        runCheck()
    }

    private func apply(_ report: GuardReport) {
        status = report.status
        detailLines = report.detailLines
    }

    private func errorDescription(_ error: Error) -> String {
        if let guardError = error as? GuardError {
            return guardError.description
        }
        return error.localizedDescription
    }
}

struct DisplayRow: Identifiable, Equatable {
    enum Kind: Equatable {
        case title
        case subtitle
        case detail
    }

    let id: String
    let kind: Kind
    let text: String
    let colorHex: String
}
