import SwiftUI

#if SWIFT_PACKAGE
import ClaudeIPGuardCore
#endif

struct ContentView: View {
    @EnvironmentObject private var viewModel: GuardViewModel

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(spacing: 12) {
                        ForEach(viewModel.displayRows) { row in
                            StatusDisplayRow(row: row)
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.top, 18)
                    .padding(.bottom, 10)
                }

                Divider()

                HStack(spacing: 12) {
                    Button {
                        viewModel.runCheck()
                    } label: {
                        Label("重新检测", systemImage: "arrow.clockwise")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(viewModel.isChecking)

                    Button {
                        viewModel.isShowingSettings = true
                    } label: {
                        Label("设置", systemImage: "slider.horizontal.3")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 14)
                .background(Color.white)
            }
            .background(Color.white)
            .navigationTitle("Claude IP Guard")
            .sheet(isPresented: $viewModel.isShowingSettings) {
                SettingsView(settings: viewModel.settings) { settings in
                    viewModel.applySettings(settings)
                }
            }
            .onAppear {
                viewModel.checkOnAppear()
            }
        }
    }
}

struct StatusDisplayRow: View {
    let row: DisplayRow

    var body: some View {
        HStack(alignment: row.kind == .title ? .center : .top, spacing: 10) {
            if row.kind == .title {
                Circle()
                    .fill(Color(hex: row.colorHex))
                    .overlay(
                        Circle()
                            .stroke(Color.black.opacity(0.16), lineWidth: 1)
                    )
                    .frame(width: 34, height: 34)
            }

            Text(row.text)
                .font(font)
                .fontWeight(row.kind == .title ? .bold : .regular)
                .foregroundStyle(Color(hex: row.colorHex))
                .lineLimit(row.kind == .title ? 2 : nil)
                .minimumScaleFactor(0.78)
                .fixedSize(horizontal: false, vertical: true)

            Spacer(minLength: 0)
        }
        .padding(.horizontal, row.kind == .title ? 14 : 16)
        .padding(.vertical, row.kind == .title ? 10 : 9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(hex: "#e9e9e9"))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
    }

    private var font: Font {
        switch row.kind {
        case .title:
            return .system(size: 30, weight: .bold, design: .default)
        case .subtitle:
            return .system(size: 16, weight: .semibold, design: .default)
        case .detail:
            return .system(size: 16, weight: .regular, design: .monospaced)
        }
    }
}

extension Color {
    init(hex: String) {
        let cleaned = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var value: UInt64 = 0
        Scanner(string: cleaned).scanHexInt64(&value)
        let red: UInt64
        let green: UInt64
        let blue: UInt64
        switch cleaned.count {
        case 6:
            red = (value >> 16) & 0xff
            green = (value >> 8) & 0xff
            blue = value & 0xff
        default:
            red = 0
            green = 0
            blue = 0
        }
        self.init(
            .sRGB,
            red: Double(red) / 255,
            green: Double(green) / 255,
            blue: Double(blue) / 255,
            opacity: 1
        )
    }
}
