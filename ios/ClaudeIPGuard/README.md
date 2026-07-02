# Claude IP Guard for iOS

SwiftUI iOS version of the desktop Claude IP Guard.

## Run in Xcode

1. Open `ClaudeIPGuard.xcodeproj`.
2. Select the `ClaudeIPGuard` target.
3. Set your Apple development team in Signing & Capabilities.
4. Run on an iPhone simulator or device.

The iOS app defaults to:

- Allowed IP: `38.15.0.237`
- Country: `US`
- Proxy: blank, which means the phone's current network, cellular route, or system VPN

If the proxy is running on the iPhone itself, enter that local proxy URL. If the proxy is running on another device, enter that reachable LAN proxy URL. Leaving proxy blank is the right setting when the phone's cellular data or system VPN already provides the intended route.

The app icon is generated from the desktop `tools/claude-ip-guard.png` asset.

## Verify Without Full Xcode

This directory also has a Swift Package so the shared logic and SwiftUI files can be checked with Command Line Tools:

```bash
swift run ClaudeIPGuardCoreSmokeTests
swift build --target ClaudeIPGuardApp
```

## Structure

- `App/`: SwiftUI app, settings sheet, view model, and local settings storage.
- `Shared/ClaudeIPGuardCore/`: reusable parsing, network, and SAFE/UNSAFE decision logic.
- `Tests/ClaudeIPGuardCoreTests/`: framework-free smoke tests for the shared core.
- `Support/Info.plist`: iOS app metadata and the `ip-api.com` HTTP exception.

## Checks

The iOS app performs the same core checks as the desktop tool:

- default egress IP through `ip-api.com`
- Claude egress IP through `claude.ai/cdn-cgi/trace`
- optional HTTPS egress through `ifconfig.me`
- supplemental risk data through `ip.net.coffee`
