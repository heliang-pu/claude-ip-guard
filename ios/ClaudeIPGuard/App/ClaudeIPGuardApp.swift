import SwiftUI

#if SWIFT_PACKAGE
import ClaudeIPGuardCore
#endif

@main
struct ClaudeIPGuardApp: App {
    @StateObject private var viewModel = GuardViewModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(viewModel)
        }
    }
}
