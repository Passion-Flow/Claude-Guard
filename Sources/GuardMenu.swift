import AppKit
import SwiftUI

struct GuardMenu: View {
    @ObservedObject var controller: GuardController
    let language: GuardLanguage
    var demo = false
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.openWindow) private var openWindow

    private var p: GuardPalette { GuardPalette(dark: colorScheme == .dark) }
    private func tr(_ key: String) -> String { GuardText(key)[language] }

    var body: some View {
        VStack(alignment: .leading, spacing: 13) {
            HStack {
                Label("Claude Guard", systemImage: "shield.lefthalf.filled")
                    .font(.system(size: 21, weight: .semibold, design: .serif))
                Spacer()
                if demo { Text(tr("Preview")).font(.caption).foregroundStyle(p.caution) }
                else {
                    Circle().fill(controller.isOpen ? p.good : p.caution).frame(width: 8, height: 8)
                        .accessibilityLabel(controller.stateTitle[language])
                }
            }
            Text(controller.stateTitle[language]).font(.callout.weight(.semibold))
                .foregroundStyle(controller.isOpen ? p.good : p.caution)
            HStack(spacing: 9) {
                tile(tr("Download"), TunnelRates.format(controller.rates?.received, language: language), "arrow.down")
                tile(tr("Upload"), TunnelRates.format(controller.rates?.sent, language: language), "arrow.up")
            }
            HStack(spacing: 9) {
                let exit = controller.status?.observed
                tile(tr("Observed exit"), exit == "-" ? "—" : exit ?? "—", "globe")
                tile(tr("Tunnel"), controller.status?.interface ?? "—", "network")
            }
            Text(tr("Rates come from system tunnel counters."))
                .font(.caption).foregroundStyle(p.secondary)
            Rectangle().fill(p.line).frame(height: 1)
            Button {
                openWindow(id: "dashboard")
                NSApp.activate(ignoringOtherApps: true)
            } label: {
                HStack {
                    Text(tr("Open Claude Guard"))
                    Spacer()
                    Image(systemName: "arrow.up.right")
                }
                .padding(.horizontal, 5)
            }
            .buttonStyle(GuardButton(palette: p, primary: true))
        }
        .padding(17)
        .frame(width: 355)
        .background(p.canvas)
        .foregroundStyle(p.ink)
    }

    private func tile(_ title: String, _ value: String, _ icon: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: icon)
                .font(.caption).foregroundStyle(p.secondary)
            Text(value).font(.system(size: 13, weight: .medium, design: .monospaced)).lineLimit(1)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(p.surface, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(p.line))
    }
}
