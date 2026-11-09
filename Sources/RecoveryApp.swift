import AppKit
import SwiftUI

struct RecoveryApplication: App {
    @AppStorage("language", store: GuardPolicy.preferences) private var language = GuardLanguage.initial
    @AppStorage("appearance", store: GuardPolicy.preferences) private var appearance = GuardAppearance.system

    var body: some Scene {
        WindowGroup(GuardText("Claude Guard Recovery")[language]) {
            RecoveryWindow(language: $language, appearance: $appearance)
                .frame(minWidth: 490, minHeight: 285)
                .preferredColorScheme(appearance.scheme)
                .environment(\.locale, language.locale)
        }
        .defaultSize(width: 490, height: 285)
    }
}

private struct RecoveryWindow: View {
    @Binding var language: GuardLanguage
    @Binding var appearance: GuardAppearance
    @Environment(\.colorScheme) private var colorScheme
    @State private var working = false
    @State private var confirmation = false
    @State private var result: GuardText?

    private var palette: GuardPalette { GuardPalette(dark: colorScheme == .dark) }
    private func tr(_ key: String) -> String { GuardText(key)[language] }

    var body: some View {
        VStack(alignment: .leading, spacing: 15) {
            Label(tr("Local network recovery"), systemImage: "shield.lefthalf.filled")
                .font(.system(.title2, design: .serif).bold())
            Text(tr("Use the Mac administrator password to remove this session’s rules. This tool works offline."))
            Text(tr("Close Claude before restoring. If the VPN is still disconnected, apps may connect directly."))
                .foregroundStyle(palette.secondary)
            HStack {
                Button(tr("Restore network…")) { confirmation = true }
                    .buttonStyle(GuardButton(palette: palette, primary: true))
                    .disabled(working)
                if working { ProgressView().controlSize(.small) }
            }
            if let result { Text(result[language]).textSelection(.enabled) }
            HStack(spacing: 20) {
                GuardDropdown(tr("Language"), selection: $language, choices: GuardLanguage.allCases, palette: palette) { $0.name }
                GuardDropdown(tr("Appearance"), selection: $appearance, choices: GuardAppearance.allCases, palette: palette) { $0.title(language) }
            }
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .foregroundStyle(palette.ink)
        .background(palette.canvas)
        .alert(tr("Remove device protection?"), isPresented: $confirmation) {
            Button(tr("Remove session rules"), role: .destructive) { restore() }
            Button(tr("Cancel"), role: .cancel) {}
        } message: {
            Text(tr("This removes the Claude Guard rules. Check the VPN connection separately."))
        }
    }

    private func restore() {
        working = true
        result = nil
        Task {
            let command = await Task.detached { Tools.admin(["stop"], background: false) }.value
            working = false
            result = command.code == 0
                ? GuardText("The Claude Guard rules are no longer active.")
                : GuardText("Recovery did not complete. Retry or restart this Mac to clear the session rules.")
        }
    }
}
