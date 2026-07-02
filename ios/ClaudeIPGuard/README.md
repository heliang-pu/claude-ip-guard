# Claude IP Guard iOS 工程

这是 Claude IP Guard 的 SwiftUI iOS 版本。

## 默认配置

App 默认配置为：

- 出口 IP：`38.15.0.237`
- 国家/地区：`US`
- 代理：留空

代理留空表示使用 iPhone 当前网络、蜂窝数据或系统 VPN。如果代理就在 iPhone 上运行，可以填写手机本地代理地址；如果代理在局域网其他设备上，需要填写手机能访问到的局域网代理地址。

## Xcode 运行

1. 打开 `ClaudeIPGuard.xcodeproj`。
2. 选择 `ClaudeIPGuard` target。
3. 在 Signing & Capabilities 里选择你的 Apple 开发者 Team。
4. 顶部运行目标选择 iPhone 真机或模拟器。
5. 点击运行。

真机首次安装后，如果 iPhone 提示开发者未受信任，到 `设置 -> 通用 -> VPN 与设备管理` 里信任开发者证书。

## 命令行验证

这个目录也包含 Swift Package，可以不用完整 Xcode 先检查共享逻辑和 SwiftUI target：

```bash
swift run ClaudeIPGuardCoreSmokeTests
swift build --target ClaudeIPGuardApp
```

构建 iOS 工程：

```bash
xcodebuild -project ClaudeIPGuard.xcodeproj \
  -scheme ClaudeIPGuard \
  -destination 'generic/platform=iOS' \
  build
```

## 工程结构

- `App/`：SwiftUI App、设置页、ViewModel、本地设置存储
- `Shared/ClaudeIPGuardCore/`：解析、网络请求和 SAFE/UNSAFE 判断逻辑
- `Tests/ClaudeIPGuardCoreTests/`：不依赖 XCTest 的核心逻辑 smoke tests
- `Support/Info.plist`：iOS 元数据和 `ip-api.com` HTTP 例外

## 检测内容

iOS 版和桌面版使用同一套核心判断思路：

- 通过 `ip-api.com` 检测默认出口 IP
- 通过 `claude.ai/cdn-cgi/trace` 检测 Claude AI 出口 IP
- 可选通过 `ifconfig.me` 做 HTTPS 二次校验
- 通过 `ip.net.coffee` 获取补充风险信息

只有出口 IP、国家/地区和启用的二次校验都符合设置时，首页才会显示 `SAFE - 可以打开 Claude`。
