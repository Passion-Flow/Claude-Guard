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
        .alert(tr("Enable device protection"), isPresented: Binding(
            get: { startTrial != nil }, set: { if !$0 { startTrial = nil } }
        )) {
            Button(tr("Continue and authorize")) {
                if let trial = startTrial { controller.begin(trial: trial) }
                startTrial = nil
            }
            Button(tr("Cancel"), role: .cancel) { startTrial = nil }
        } message: {
            Text(startTrial == true
                 ? tr("Start the trial locally. macOS will ask for administrator access and reset existing connections. Blocking remains in effect when the trial expires.")
                 : tr("Enable the approved route and recheck its exit. App traffic stays blocked when the VPN is unavailable."))
        }
        .alert(tr("Restore network"), isPresented: $showRestore) {
            Button(tr("Remove session rules"), role: .destructive) { controller.restore() }
            Button(tr("Cancel"), role: .cancel) {}
        } message: {
            Text(tr("Close Claude first. Removing protection can restore direct Internet access if the VPN is disconnected."))
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
                    HStack {
                        metric(tr("Approved exit"), endpointDisplay(controller.status?.expected ?? controller.configuration.exit))
                        metric(tr("Observed exit"), endpointDisplay(controller.status?.observed))
                        metric(tr("Tunnel"), endpointDisplay(controller.status?.interface))
                    }
                    HStack(spacing: 9) {
                        Button(tr("60-second trial")) { startTrial = true }
                            .buttonStyle(GuardButton(palette: palette, primary: true))
                            .disabled(controller.active || controller.busy || controller.detectingEndpoint)
                        Button(controller.active ? tr("Continue protection") : tr("Enable last route")) { startTrial = false }
                            .buttonStyle(GuardButton(palette: palette))
                            .disabled(!controller.canGoLive)
                        Spacer(minLength: 0)
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
                        Text(tr("Evidence from the node link. Shadowrocket performs the actual handshake."))
                            .font(.caption).foregroundStyle(palette.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            configuration
            card {
                VStack(alignment: .leading, spacing: 11) {
                    sectionTitle(tr("Open while protected"), "square.grid.2x2")
                    HStack(spacing: 8) {
                        ForEach(Channel.allCases) { channel in
                            Button { controller.launch(channel) } label: {
                                Label(channel.title[language], systemImage: channel.symbol)
                            }
                            .buttonStyle(GuardButton(palette: palette))
                            .disabled(!controller.isOpen)
                        }
                    }
                }
            }
            Text(tr("The guardian continues after the window closes. Enable protection again after a Mac restart."))
                .font(.caption).foregroundStyle(palette.secondary)
        }
    }

    private var configuration: some View {
        card {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    sectionTitle(tr("Node and detection"), "slider.horizontal.3")
                    Spacer()
                    Button(controller.checking ? tr("Detecting…") : tr("Detect again")) { controller.detect() }
                        .buttonStyle(GuardButton(palette: palette))
                        .disabled(controller.checking)
                }
                if let check = controller.check {
                    Text(check.vpnConnected
                         ? GuardText("Shadowrocket detected · Default interface %1$@", .plain(check.defaultInterface))[language]
                         : GuardText("Shadowrocket connection unconfirmed · Default interface %1$@", .plain(check.defaultInterface))[language])
                    .font(.caption).foregroundStyle(palette.secondary)
                }
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 12) {
                        field(tr("Node address"), text: $controller.configuration.peer)
                        field(tr("Node port"), text: $controller.configuration.port).frame(width: 110)
                        GuardDropdown(tr("Transport"), selection: $controller.configuration.transport,
                                      choices: ["tcp", "udp"], palette: palette) { $0.uppercased() }
                        .frame(width: 150)
                    }
                    HStack(spacing: 12) {
                        field(tr("Approved exit (defaults to node)"), text: $controller.configuration.expected)
                        GuardDropdown(tr("Tunnel"), selection: $controller.configuration.interface,
                                      choices: [""] + tunnelChoices, palette: palette) { $0.isEmpty ? tr("Select") : $0 }
                        .frame(width: 190)
                    }
                    HStack(spacing: 8) {
                        Button(controller.detectingEndpoint ? tr("Detecting…") : tr("Detect port and protocol")) {
                            controller.detectEndpoint()
                        }
                        .buttonStyle(GuardButton(palette: palette))
                        .disabled(controller.detectingEndpoint)
                        Button(tr("Read node from clipboard")) { controller.importNode() }
                            .buttonStyle(GuardButton(palette: palette))
                        if !controller.endpointCandidates.isEmpty {
                            GuardDropdown(tr("Select connection"), choices: controller.endpointCandidates,
                                          palette: palette, label: { $0.label }, onSelect: controller.useEndpoint)
                                .frame(minWidth: 130, maxWidth: 205)
                        }
                    }
                }
                .disabled(controller.active || controller.busy)
            }
        }
    }

    private var chain: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack(spacing: 9) {
                pill(controller.stateTitle[language], color: tone)
                Text(tr("Policy state · Verify on the target Mac"))
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
            layer(5, "macwindow.on.rectangle", tr("App traffic"), tr("Device-wide"),
                  tr("The same rule covers browsers, desktop apps, VS Code, and Terminal. A wrong exit or disconnect blocks traffic again."),
                  tr("Runtime filtering · No payload logging"))
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
                    Text(tr("Run detection or a trial to record events here."))
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
            if controller.active || demo {
                Text(text.wrappedValue.isEmpty ? "—" : text.wrappedValue)
                    .font(.system(.callout, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 4)
                    .background(palette.canvas, in: RoundedRectangle(cornerRadius: 5))
                    .accessibilityLabel(title)
                    .accessibilityValue(text.wrappedValue)
            } else {
                TextField(title, text: text).textFieldStyle(.roundedBorder).accessibilityLabel(title)
            }
        }
    }

    private func pill(_ text: String, color: Color) -> some View {
        Text(text).font(.caption.weight(.semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 8).padding(.vertical, 5)
            .background(color.opacity(0.11), in: Capsule())
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
