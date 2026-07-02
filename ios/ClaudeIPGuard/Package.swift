// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "ClaudeIPGuardIOS",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "ClaudeIPGuardCore",
            targets: ["ClaudeIPGuardCore"]
        ),
        .executable(
            name: "ClaudeIPGuardApp",
            targets: ["ClaudeIPGuardApp"]
        ),
        .executable(
            name: "ClaudeIPGuardCoreSmokeTests",
            targets: ["ClaudeIPGuardCoreSmokeTests"]
        ),
    ],
    targets: [
        .target(
            name: "ClaudeIPGuardCore",
            path: "Shared/ClaudeIPGuardCore"
        ),
        .executableTarget(
            name: "ClaudeIPGuardApp",
            dependencies: ["ClaudeIPGuardCore"],
            path: "App",
            exclude: ["Assets.xcassets"],
            swiftSettings: [.define("SWIFT_PACKAGE")]
        ),
        .executableTarget(
            name: "ClaudeIPGuardCoreSmokeTests",
            dependencies: ["ClaudeIPGuardCore"],
            path: "Tests/ClaudeIPGuardCoreTests"
        ),
    ]
)
