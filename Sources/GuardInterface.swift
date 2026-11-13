import AppKit
import SwiftUI

struct GuardApplication: App {
    @StateObject private var controller = GuardController()
    @AppStorage("language", store: GuardPolicy.preferences) private var language = GuardLanguage.initial
    @AppStorage("appearance", store: GuardPolicy.preferences) private var appearance = GuardAppearance.system

    var body: some Scene {
        Window("Claude Guard", id: "dashboard") {
            GuardWindow(controller: controller, language: $language, appearance: $appearance)
                .frame(minWidth: 880, minHeight: 650)
                .preferredColorScheme(appearance.scheme)
                .environment(\.locale, language.locale)
                .task { if controller.check == nil { controller.detect() } }
        }
        .defaultSize(width: 1060, height: 790)

        MenuBarExtra {
            GuardMenu(controller: controller, language: language)
                .preferredColorScheme(appearance.scheme)
                .environment(\.locale, language.locale)
        } label: {
            Image(systemName: controller.isOpen ? "checkmark.shield.fill" :
                    (controller.rulesConfirmed ? "lock.shield.fill" : "shield"))
                .accessibilityLabel(GuardText("Claude Guard quick panel")[language])
        }
        .menuBarExtraStyle(.window)
    }
}

enum GuardPane: String, CaseIterable {
    case overview, path, events

    var title: GuardText {
        switch self {
        case .overview: return GuardText("Overview")
        case .path: return GuardText("Traffic path")
        case .events: return GuardText("Monitoring & reports")
        }
    }
    var icon: String {
        switch self {
        case .overview: return "rectangle.grid.2x2"
        case .path: return "point.3.connected.trianglepath.dotted"
        case .events: return "list.bullet.rectangle"
        }
    }
}

struct GuardWindow: View {
    @ObservedObject var controller: GuardController
    @Binding var language: GuardLanguage
    @Binding var appearance: GuardAppearance
    @Environment(\.colorScheme) private var colorScheme
    @State private var pane: GuardPane
    @State private var startTrial: Bool?
    @State private var showRestore = false
    let demo: Bool

    init(controller: GuardController, language: Binding<GuardLanguage>, appearance: Binding<GuardAppearance>,
         pane: GuardPane = .overview, demo: Bool = false) {
        self.controller = controller
        _language = language
        _appearance = appearance
        _pane = State(initialValue: pane)
        self.demo = demo
    }

    private var palette: GuardPalette { GuardPalette(dark: colorScheme == .dark) }
    private func tr(_ key: String) -> String { GuardText(key)[language] }
    private var tone: Color {
        if controller.isOpen { return palette.good }
        if controller.isRechecking || controller.legacyPolicy || controller.stale { return palette.caution }
        if controller.active { return palette.bad }
        return palette.secondary
    }

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Rectangle().fill(palette.line).frame(width: 1)
            if demo { pageContent }
            else { ScrollView { pageContent } }
        }
        .foregroundStyle(palette.ink)
        .background(palette.canvas)
        .tint(palette.accent)
        .alert(tr("Restore network"), isPresented: $showRestore) {
            Button(tr("Remove session rules"), role: .destructive) { controller.restore() }
            Button(tr("Cancel"), role: .cancel) {}
        } message: {
            Text(tr("Close your apps first. Removing protection can restore direct Internet access if the VPN is disconnected."))
        }

    }

    private var pageContent: some View {
        VStack(alignment: .leading, spacing: 20) {
            pageHeading
            switch pane {
            case .overview: overview
            case .path: chain
            case .events: history
            }
        }
        .frame(maxWidth: 900)
        .padding(.horizontal, 33)
        .padding(.vertical, 27)
        .frame(maxWidth: .infinity, maxHeight: demo ? .infinity : nil, alignment: .top)
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 9) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundStyle(palette.accent)
                    .frame(width: 35, height: 35)
                    .background(palette.highlight, in: RoundedRectangle(cornerRadius: 10))
                VStack(alignment: .leading, spacing: 2) {
                    Text("Claude Guard").font(.system(size: 18, weight: .semibold, design: .serif))
                    Text(tr("Network guard")).font(.caption).foregroundStyle(palette.secondary)
                }
            }
            .padding(.bottom, 8)
            ForEach(GuardPane.allCases, id: \.self) { item in
                Button { pane = item } label: {
                    Label(item.title[language], systemImage: item.icon)
                        .font(.system(size: 13, weight: pane == item ? .semibold : .regular))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 10)
                        .background(pane == item ? palette.highlight : Color.clear, in: RoundedRectangle(cornerRadius: 9))
                        .foregroundStyle(pane == item ? palette.accent : palette.ink)
                }
                .buttonStyle(.plain)
            }
            Spacer()
            Rectangle().fill(palette.line).frame(height: 1)
            GuardDropdown(tr("Language"), selection: $language, choices: GuardLanguage.allCases, palette: palette) { $0.name }
            GuardDropdown(tr("Appearance"), selection: $appearance, choices: GuardAppearance.allCases, palette: palette) { $0.title(language) }
            Text("v" + GuardPolicy.version + " · " + tr("Beta"))
                .font(.caption.monospaced())
                .foregroundStyle(palette.secondary)
        }
        .padding(19)
        .padding(.top, 7)
        .frame(width: 214)
        .background(palette.sidebar)
    }

    private var pageHeading: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 8) {
                Text(pane.title[language])
                    .font(.system(size: 36, weight: .regular, design: .serif))
                Text(pageSubtitle)
                    .font(.system(size: 13)).foregroundStyle(palette.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            if demo { pill(tr("Preview data"), color: palette.caution) }
        }
    }

    private var pageSubtitle: String {
        switch pane {
        case .overview: return tr("Verify the exit before allowing apps to connect.")
        case .path: return tr("See the policy and evidence at each step from local access to app traffic.")
        case .events: return tr("Review local checks, blocks, recoveries, and reports.")
        }
    }

    private var overview: some View {
        VStack(alignment: .leading, spacing: 16) {
            card {
                VStack(alignment: .leading, spacing: 15) {
                    HStack(spacing: 9) {
                        Image(systemName: "shield.checkered")
                            .foregroundStyle(tone).font(.title3)
                        Text(controller.stateTitle[language]).font(.title3.weight(.semibold))
                        Spacer()
                        if let seconds = controller.countdown {
                            pill(GuardText("Trial · %1$@s", .plain(String(seconds)))[language], color: palette.caution)
                        }
                        if controller.busy { ProgressView().controlSize(.small) }
                    }
                    Text(controller.stateExplanation[language])
                        .font(.callout).foregroundStyle(palette.secondary).fixedSize(horizontal: false, vertical: true)
                    if controller.rulesConfirmed && !controller.isOpen {
                        Text(tr("Local TCP/IP connections pause until protection opens."))
                            .font(.caption).foregroundStyle(palette.secondary)
                    }
                    HStack {
                        metric(tr("Approved exit"), endpointDisplay(controller.status?.expected ?? controller.configuration.exit))
                        metric(tr("Observed exit"), endpointDisplay(controller.status?.observed))
                        metric(tr("Tunnel"), endpointDisplay(controller.status?.interface))
                    }
                    HStack(spacing: 9) {
                        if controller.paused {
                            Button(tr("Resume protection")) { controller.begin(trial: false) }
                                .buttonStyle(GuardButton(palette: palette, primary: true)).disabled(controller.busy)
                        } else if !controller.automaticEnabled {
                            Button(tr("Enable automatic protection")) { controller.retryAutomaticSetup() }
                                .buttonStyle(GuardButton(palette: palette, primary: true)).disabled(controller.busy || controller.automaticChecking)
                        }
                        if controller.automaticChecking { ProgressView().controlSize(.small) }
                        Text(tr(controller.automaticChecking ? "Reading the active Shadowrocket profile…" : "Automatic detection and protection"))
                            .font(.callout).foregroundStyle(palette.secondary)
                        Spacer()
                        Button(tr("Pause protection")) { controller.pauseProtection() }
                            .buttonStyle(GuardButton(palette: palette)).disabled(!controller.mayPause)
                    }
                    HStack(spacing: 9) {
                        Text(controller.persistent ? tr("Startup protection on") : tr("Startup monitoring enabled"))
                            .font(.caption).foregroundStyle(palette.secondary)
                        Spacer(minLength: 0)
                        Button(tr("Open offline recovery")) { controller.openRecovery() }
                            .buttonStyle(GuardButton(palette: palette))
                        Button(tr("Restore network")) { showRestore = true }
                            .buttonStyle(GuardButton(palette: palette))
                            .disabled(!controller.mayRestore)
                    }
                }
            }
            HStack(alignment: .top, spacing: 13) {
                card {
                    VStack(alignment: .leading, spacing: 12) {
                        sectionTitle(tr("Tunnel traffic"), "arrow.up.arrow.down")
                        HStack(spacing: 10) {
                            metric(tr("Download"), TunnelRates.format(controller.rates?.received, language: language))
                            metric(tr("Upload"), TunnelRates.format(controller.rates?.sent, language: language))
                        }
                        Text(tr("System interface counters · No packet contents"))
                            .font(.caption).foregroundStyle(palette.secondary)
                    }
                }
                card {
                    VStack(alignment: .leading, spacing: 12) {
                        sectionTitle(tr("Transport security"), "lock.shield")
                        Text(controller.currentTransport.title[language]).font(.system(.body, design: .monospaced))
                        Text(tr("Only connection and encryption metadata is read. Shadowrocket performs the actual handshake."))
                            .font(.caption).foregroundStyle(palette.secondary).fixedSize(horizontal: false, vertical: true)
                        Divider()
                        Text(controller.riskStatus[language]).font(.callout.weight(.semibold))
                        if let checkedAt = controller.status?.riskCheckedAt {
                            Text(GuardCopy.date(checkedAt, language)).font(.caption).foregroundStyle(palette.secondary)
                        }
                    }
                }
            }
            automaticConfiguration
            Text(controller.persistent
                 ? tr("Startup protection is on. Restore network removes it.")
                 : tr("Detection, stability checks, risk admission and recovery run automatically."))
                .font(.caption).foregroundStyle(palette.secondary)
        }
    }

    private var automaticConfiguration: some View {
        card {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    sectionTitle(tr("Automatic setup"), "sparkles")
                    Spacer()
                    Button(tr("Detect again")) { controller.retryAutomaticSetup() }
                        .buttonStyle(GuardButton(palette: palette))
                        .disabled(controller.busy || controller.automaticChecking || controller.paused)
                }
                Text(tr("Connect Shadowrocket once. The active profile, endpoint, tunnel and exit are detected without manual fields or a personal API key."))
                    .font(.callout).foregroundStyle(palette.secondary).fixedSize(horizontal: false, vertical: true)
                Text(tr("Risk admission requires a residential classification, score at most 10, clear risk flags and the approved region. Unavailable evidence keeps traffic blocked."))
                    .font(.caption).foregroundStyle(palette.secondary).fixedSize(horizontal: false, vertical: true)
                DisclosureGroup(tr("Advanced preferences")) {
                    GuardDropdown(tr("Approved exit region"), selection: Binding(
                        get: { controller.configuration.approvedRegion ?? "US" },
                        set: { controller.configuration.approvedRegion = $0 }
                    ), choices: GuardRiskPolicy.regions, palette: palette) { region in
                        Locale(identifier: language == .chinese ? "zh_Hans" : "en").localizedString(forRegionCode: region) ?? region
                    }.disabled(controller.active || controller.automaticChecking)
                }
            }
        }
    }

    private var chain: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack(spacing: 9) {
                pill(controller.stateTitle[language], color: tone)
                Text(tr("Policy state · Evidence scope"))
                    .font(.caption).foregroundStyle(palette.secondary)
                Spacer()
            }
            layer(1, "wifi", tr("Local access"), tr("Physical interface"),
                  tr("Wi-Fi or Ethernet provides local access. The filter allows network maintenance and blocks ordinary direct traffic."),
                  tr("The fixed VPS is the public exception"))
            layer(2, "server.rack", tr("Pinned VPS connection"), tr("Outer transport"),
                  tr("The local network carries the connection to the configured node. Shadowrocket and the server negotiate encryption."),
                  controller.currentTransport.title[language])
            layer(3, "lock.shield", tr("Approved tunnel"), tr("Service binding"),
                  tr("Reconnection is tied to the original Shadowrocket service. The candidate tunnel starts with exit probes while app traffic stays blocked."),
                  tr("Allow supported tunnel traffic only"))
            layer(4, "checkmark.circle", tr("Exit and stability"), tr("Release gate"),
                  tr("Six consecutive exit checks span at least 15 seconds on the same tunnel and visible route. Failures or changes restart the window."),
                  tr("Primary and backup HTTPS probes"))
            layer(5, "checkmark.shield", tr("Risk admission"), tr("Required provider evidence"),
                  tr("The approved region, residential classification, low score and clear risk flags are required. Missing or expired evidence keeps apps blocked."),
                  controller.riskStatus[language])
            layer(6, "macwindow.on.rectangle", tr("App traffic"), tr("Device-wide"),
                  tr("The same rule covers browsers, desktop apps, VS Code, and Terminal. A wrong exit or disconnect blocks traffic again."),
                  tr("Runtime filtering · No payload logging"))
            layer(7, "arrow.clockwise.circle", tr("Guardian and recovery"), tr("System supervision"),
                  tr("The system guardian retains approved configuration, repairs damaged rules and starts fresh validation after recovery. Offline restoration remains a separate local action."),
                  tr("Restart never reuses a previous exit observation"))
            ServiceDiagnosticsCard(controller: controller, diagnostics: controller.serviceDiagnostics,
                                   language: language, palette: palette)
            BrowserDiagnosticsCard(controller: controller, diagnostics: controller.browserDiagnostics,
                                   language: language, appearance: appearance, palette: palette)
            Text(tr("The outer connection still uses the local ISP. This view shows rule state and exit probes. Packet-level verification is performed on the target Mac."))
                .font(.caption).foregroundStyle(palette.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }

    private func layer(_ step: Int, _ icon: String, _ title: String, _ group: String,
                       _ body: String, _ detail: String) -> some View {
        card {
            HStack(alignment: .top, spacing: 13) {
                Text(String(format: "%02d", step)).font(.system(.caption, design: .monospaced))
                    .foregroundStyle(palette.accent)
                    .frame(width: 31, height: 31)
                    .background(palette.highlight, in: RoundedRectangle(cornerRadius: 9))
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Label(title, systemImage: icon).font(.system(size: 15, weight: .semibold))
                        Spacer()
                        Text(group).font(.caption).foregroundStyle(palette.secondary)
                    }
                    Text(body).font(.callout).foregroundStyle(palette.secondary).fixedSize(horizontal: false, vertical: true)
                    Text(detail).font(.caption.weight(.semibold)).foregroundStyle(palette.accent)
                }
            }
        }
    }

    private var history: some View {
        card {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    sectionTitle(tr("Local events"), "list.bullet.rectangle")
                    Spacer()
                    Button(tr("Export report…")) { controller.saveReport(language: language) }
                        .buttonStyle(GuardButton(palette: palette, primary: true))
                }
                if controller.events.isEmpty {
                    Text(tr("Detection and protection events appear here automatically."))
                        .foregroundStyle(palette.secondary)
                }
                ForEach(controller.events) { event in
                    Rectangle().fill(palette.line).frame(height: 1)
                    HStack(alignment: .top) {
                        Text(GuardCopy.phase(event.state)[language]).font(.callout.weight(.semibold))
                        Spacer()
                        Text(GuardCopy.date(event.at, language)).font(.caption).foregroundStyle(palette.secondary)
                    }
                    Text(event.description(in: language) + (event.ip.map { tr("  Exit ") + $0 } ?? ""))
                        .font(.callout).foregroundStyle(palette.secondary).textSelection(.enabled)
                }
            }
        }
    }

    private var tunnelChoices: [String] {
        let current = controller.configuration.interface
        return Array(Set((controller.check?.tunnels ?? []) + (current.isEmpty ? [] : [current]))).sorted()
    }

    private func card<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        content()
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(palette.surface, in: RoundedRectangle(cornerRadius: 13))
            .overlay(RoundedRectangle(cornerRadius: 13).strokeBorder(palette.line))
    }

    private func sectionTitle(_ title: String, _ icon: String) -> some View {
        Label(title, systemImage: icon).font(.system(size: 14, weight: .semibold))
    }

    private func endpointDisplay(_ text: String?) -> String {
        guard let text, !text.isEmpty, text != "-" else { return "—" }
        return text
    }

    private func metric(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.caption).foregroundStyle(palette.secondary)
            Text(value).font(.system(size: 14, weight: .medium, design: .monospaced))
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func field(_ title: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.caption).foregroundStyle(palette.secondary)
            Group {
                if controller.active || demo {
                    Text(text.wrappedValue.isEmpty ? "—" : text.wrappedValue)
                        .lineLimit(1)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityLabel(title)
                        .accessibilityValue(text.wrappedValue)
                } else {
                    TextField("", text: text).textFieldStyle(.plain).accessibilityLabel(title)
                }
            }
            .font(.system(size: 12, weight: .medium, design: .monospaced))
            .padding(.horizontal, 10)
            .frame(height: 30)
            .background(palette.surface, in: RoundedRectangle(cornerRadius: 7))
            .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(palette.line))
        }
    }

    private func pill(_ text: String, color: Color) -> some View {
        Text(text).font(.caption.weight(.semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 8).padding(.vertical, 5)
            .background(color.opacity(0.11), in: Capsule())
    }
}

struct ServiceDiagnosticsCard: View {
    @ObservedObject var controller: GuardController
    @ObservedObject var diagnostics: ServiceDiagnostics
    let language: GuardLanguage
    let palette: GuardPalette

    private func tr(_ key: String) -> String { GuardText(key)[language] }

    var body: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack {
                Label(tr("Anonymous service path"), systemImage: "point.3.connected.trianglepath.dotted")
                    .font(.system(size: 15, weight: .semibold))
                Spacer()
                Button(diagnostics.checking ? tr("Checking…") : tr("Check service path")) {
                    if let status = controller.status { diagnostics.start(status) }
                }
                .buttonStyle(GuardButton(palette: palette))
                .disabled(!controller.isOpen || controller.status?.mode != "live" || controller.busy || diagnostics.checking)
            }
            Text(tr("Service path scope")).font(.caption).foregroundStyle(palette.secondary)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(diagnostics.results) { result in
                Text(result.id + " · " + result.outcome.title[language]).font(.callout)
            }
            if let checkedAt = diagnostics.checkedAt {
                Text(GuardCopy.date(checkedAt, language)).font(.caption).foregroundStyle(palette.secondary)
            }
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(palette.surface, in: RoundedRectangle(cornerRadius: 13))
        .overlay(RoundedRectangle(cornerRadius: 13).strokeBorder(palette.line))
    }
}

struct BrowserDiagnosticsCard: View {
    @ObservedObject var controller: GuardController
    @ObservedObject var diagnostics: BrowserDiagnostics
    let language: GuardLanguage
    let appearance: GuardAppearance
    let palette: GuardPalette

    private func tr(_ key: String) -> String { GuardText(key)[language] }

    var body: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack {
                Label(tr("Browser network check"), systemImage: "network")
                    .font(.system(size: 15, weight: .semibold))
                Spacer()
                Button(tr("Open browser check")) {
                    controller.openBrowserDiagnostics(language: language, appearance: appearance)
                }
                .buttonStyle(GuardButton(palette: palette))
                .disabled(!controller.isOpen || controller.status?.mode != "live" || controller.busy)
                if diagnostics.running {
                    Button(tr("Close browser check")) { diagnostics.stop() }
                        .buttonStyle(GuardButton(palette: palette))
                }
            }
            Text(tr("Browser test scope")).font(.caption).foregroundStyle(palette.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text(tr("Enable continuous protection before starting a browser check."))
                .font(.caption).foregroundStyle(palette.secondary)
            if let evidence = diagnostics.evidence {
                Text(evidence.summary[language]).font(.callout.weight(.semibold))
                Text(GuardCopy.date(evidence.checkedAt, language)).font(.caption).foregroundStyle(palette.secondary)
            } else if let error = diagnostics.error {
                Text(error[language]).font(.callout).foregroundStyle(palette.caution)
            } else {
                Text(tr("Browser evidence unavailable")).font(.callout).foregroundStyle(palette.secondary)
            }
            Divider()
            Text(tr("External diagnostic sites use their own scoring methods."))
                .font(.caption).foregroundStyle(palette.secondary)
            HStack(spacing: 16) {
                Button("Net.Coffee") { controller.openDiagnosticSite(.netCoffee) }
                Button("fuck-claude.com") { controller.openDiagnosticSite(.browserScore) }
            }
            .buttonStyle(GuardButton(palette: palette))
            .font(.callout)
            .disabled(!controller.isOpen || controller.status?.mode != "live" || controller.busy)
        }
        .padding(17)
        .background(palette.surface, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(palette.line))
    }
}

struct GuardButton: ButtonStyle {
    let palette: GuardPalette
    var primary = false
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 12, weight: .medium))
            .padding(.horizontal, 10).padding(.vertical, 7)
            .foregroundStyle(primary ? palette.canvas : palette.ink)
            .background(primary ? palette.accent : palette.surface, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(primary ? Color.clear : palette.line))
            .opacity(!enabled ? 0.45 : configuration.isPressed ? 0.75 : 1)
    }
}
