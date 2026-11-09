import AppKit
import Foundation
import SwiftUI
import UniformTypeIdentifiers

struct GuardConfiguration: Codable, Equatable, Sendable {
    var peer = ""
    var port = ""
    var transport = "tcp"
    var expected = ""
    var interface = ""

    var exit: String { expected.isEmpty ? peer : expected }
    var endpointKey: String { peer + ":" + port + "/" + transport }

    static func validIPv4(_ value: String) -> Bool {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy {
            guard let byte = UInt8($0), String(byte) == $0 else { return false }
            return true
        }
    }

    static func validInterface(_ value: String) -> Bool {
        value.range(of: #"^utun[0-9]+$"#, options: .regularExpression) != nil
    }

    var problem: GuardText? {
        if !Self.validIPv4(peer) { return GuardText("Enter a valid numeric node address.") }
        if ["1.1.1.1", "1.0.0.1"].contains(peer) { return GuardText("The node address must be different from both health probes.") }
        if !Self.validIPv4(exit) { return GuardText("Enter a valid numeric exit address.") }
        if let value = UInt16(port), value > 0, String(value) == port { }
        else { return GuardText("Enter the node port (1–65535).") }
        if !["tcp", "udp"].contains(transport) { return GuardText("Select the node transport.") }
        if !Self.validInterface(interface) { return GuardText("Connect the node in Shadowrocket, then detect and select its tunnel.") }
        return nil
    }
}

struct Snapshot: Sendable, Equatable {
    let session: String
    let phase: String
    let time: Date
    let interface: String
    let expected: String
    let observed: String
    let reason: String
    let expiration: Date?
    let mode: String
    let trialVerified: Bool
    let serviceID: String?
    let endpointKey: String?
    let policyID: String?

    init?(_ line: String) {
        let fields = line.trimmingCharacters(in: .newlines).split(separator: "|", omittingEmptySubsequences: false)
        guard (9...13).contains(fields.count), let stamp = Double(fields[2]), stamp.isFinite,
              let until = Double(fields[7]), until.isFinite,
              ["IDLE", "VERIFYING", "LOCKED", "OPEN", "DRIFT", "ERROR"].contains(String(fields[1])) else { return nil }
        session = String(fields[0])
        phase = String(fields[1])
        time = Date(timeIntervalSince1970: stamp)
        interface = String(fields[3])
        expected = String(fields[4])
        observed = String(fields[5])
        reason = String(fields[6])
        expiration = until > 0 ? Date(timeIntervalSince1970: until) : nil
        mode = String(fields[8])
        trialVerified = fields.count >= 10 && fields[9] == "1"
        serviceID = fields.count >= 11 && UUID(uuidString: String(fields[10])) != nil ? String(fields[10]) : nil
        endpointKey = fields.count >= 12 && !fields[11].isEmpty ? String(fields[11]) : nil
        policyID = fields.count >= 13 && !fields[12].isEmpty ? String(fields[12]) : nil
    }
}

struct ApprovedRoute: Codable, Equatable {
    let endpointKey: String
    let expected: String
    let serviceID: String
}

struct GuardEvent: Codable, Identifiable {
    var id = UUID()
    var at: Date
    var state: String
    var text: String
    var english: String? = nil
    var ip: String?

    func description(in language: GuardLanguage) -> String {
        if language == .chinese { return text }
        if let english { return english }
        if let equivalent = GuardCopy.reasons.values.first(where: { $0.zh == text }) { return equivalent.en }
        if GuardCopy.eventCode(state) == "detect" { return GuardText("A local network detection check was recorded.")[language] }
        return GuardText("An event was recorded by an earlier version. Switch to Chinese to read the original note.")[language]
    }
}

struct LocalCheck: Sendable {
    let system: String
    let defaultInterface: String
    let tunnels: [String]
    let vpnConnected: Bool
    let pfPresent: Bool

    static func read() -> Self {
        let route = Tools.call("/sbin/route", ["-n", "get", "-inet", "1.1.1.1"]).text
        let routeInterface = route.split(whereSeparator: \.isNewline).compactMap { row -> String? in
            let line = row.trimmingCharacters(in: .whitespaces)
            guard line.hasPrefix("interface:") else { return nil }
            return line.dropFirst("interface:".count).trimmingCharacters(in: .whitespaces)
        }.first ?? "—"
        let interfaces = Tools.call("/sbin/ifconfig", ["-l"]).text
            .split(whereSeparator: \.isWhitespace).map(String.init).filter(GuardConfiguration.validInterface)
        let vpn = Tools.call("/usr/sbin/scutil", ["--nc", "list"]).text
            .split(whereSeparator: \.isNewline).contains { $0.contains("(Connected)") && $0.localizedCaseInsensitiveContains("Shadowrocket") }
        return Self(system: ProcessInfo.processInfo.operatingSystemVersionString, defaultInterface: routeInterface,
                    tunnels: interfaces, vpnConnected: vpn, pfPresent: FileManager.default.isExecutableFile(atPath: "/sbin/pfctl"))
    }
}

enum Tools {
    struct Result: Sendable {
        let code: Int32
        let text: String
    }

    static func call(_ executable: String, _ args: [String], input: Data? = nil) -> Result {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: executable)
        task.arguments = args
        task.standardOutput = pipe
        task.standardError = pipe
        task.standardInput = FileHandle.nullDevice
        if let input {
            let stdin = Pipe()
            task.standardInput = stdin
            do {
                try task.run()
                stdin.fileHandleForWriting.write(input)
                stdin.fileHandleForWriting.closeFile()
            } catch { return Result(code: 1, text: error.localizedDescription) }
        } else {
            do { try task.run() } catch { return Result(code: 1, text: error.localizedDescription) }
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        return Result(code: task.terminationStatus, text: String(decoding: data, as: UTF8.self))
    }

    static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    static func admin(_ args: [String], background: Bool) -> Result {
        let parts = ["/bin/sh", "-c", privilegedWorker, "claude-guard-worker"] + args
        let wrapped = parts.map(shellQuote).joined(separator: " ")
        let command = background
            ? "/usr/bin/nohup " + wrapped + " </dev/null >/dev/null 2>&1 &"
            : wrapped
        let script = """
        on run argv
            do shell script (item 1 of argv) with administrator privileges
        end run
        """
        return call("/usr/bin/osascript", ["-e", script, command])
    }
}

@MainActor
final class GuardController: ObservableObject {
    @Published var configuration: GuardConfiguration
    @Published private(set) var check: LocalCheck?
    @Published private(set) var status: Snapshot?
    @Published private(set) var events: [GuardEvent]
    @Published private(set) var busy = false
    @Published private(set) var checking = false
    @Published private(set) var detectingEndpoint = false
    @Published private(set) var endpointCandidates: [DetectedEndpoint] = []
    @Published private(set) var approvedRoute: ApprovedRoute?
    @Published private(set) var active = false
    @Published private(set) var stale = false
    @Published private(set) var countdown: Int?
    @Published var notice: GuardText?
    @Published private var reviewedTransports: [String: TransportEvidence.Kind] = [:]
    @Published private(set) var rates: TunnelRates?

    private let runtime = URL(fileURLWithPath: "/var/run/org.claudeguard.runtime", isDirectory: true)
    private var lastImportedLine: String?
    private var lastJournalText: String?
    private var requestSession: String?
    private var pendingAt: Date?
    private var timer: Timer?
    private var previousCounter: TunnelCounters?
    private let preview: Bool
    private let preferences = UserDefaults.standard

    init(preview: Bool = false) {
        self.preview = preview
        if preview {
            configuration = GuardConfiguration(port: "443", interface: "utun6")
            events = [
                GuardEvent(at: Date().addingTimeInterval(-46), state: "OPEN", text: GuardCopy.reason("stable-open").zh,
                           english: GuardCopy.reason("stable-open").en, ip: nil),
                GuardEvent(at: Date().addingTimeInterval(-64), state: "LOCKED", text: GuardCopy.reason("settling").zh,
                           english: GuardCopy.reason("settling").en, ip: nil),
            ]
            check = LocalCheck(system: "macOS", defaultInterface: "utun6", tunnels: ["utun6"], vpnConnected: true, pfPresent: true)
            let demo = "demo|OPEN|" + String(Date().timeIntervalSince1970) + "|utun6|-|-|stable-open|0|live|1|||" + GuardPolicy.id
            status = Snapshot(demo)
            reviewedTransports = [configuration.endpointKey: .reality]
            rates = TunnelRates(received: 126000, sent: 18400)
            active = true
            return
        }
        if let data = preferences.data(forKey: "configuration"),
           let saved = try? JSONDecoder().decode(GuardConfiguration.self, from: data) {
            configuration = saved
        } else { configuration = GuardConfiguration() }
        if let data = preferences.data(forKey: "events"),
           let saved = try? JSONDecoder().decode([GuardEvent].self, from: data) {
            events = saved
        } else { events = [] }
        if let data = preferences.data(forKey: "approvedRoute") {
            approvedRoute = try? JSONDecoder().decode(ApprovedRoute.self, from: data)
        }
        if let data = preferences.data(forKey: "reviewedTransports"),
           let saved = try? JSONDecoder().decode([String: TransportEvidence.Kind].self, from: data) {
            reviewedTransports = saved
        }
        lastImportedLine = preferences.string(forKey: "lastImportedLine")
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    var canGoLive: Bool {
        guard !busy, !detectingEndpoint else { return false }
        if !active {
            return approvedRoute?.endpointKey == configuration.endpointKey && approvedRoute?.expected == configuration.exit
        }
        guard let status, !stale, !legacyPolicy, status.trialVerified else { return false }
        return ["trial", "paused"].contains(status.mode) && !["ERROR", "DRIFT"].contains(status.phase)
    }
    var legacyPolicy: Bool {
        active && status.map { ["OPEN", "LOCKED"].contains($0.phase) && $0.policyID != GuardPolicy.id } == true
    }

    var rulesConfirmed: Bool {
        active && !stale && !legacyPolicy && status.map { ["OPEN", "LOCKED"].contains($0.phase) } == true
    }

    var isOpen: Bool { rulesConfirmed && status?.phase == "OPEN" && !isRechecking }
    var isRechecking: Bool { status?.reason == "probe-retry" && active && !stale }
    var mayRestore: Bool { active && !busy }
    var currentTransport: TransportEvidence.Kind {
        reviewedTransports[configuration.endpointKey] ?? .unknown
    }

    var stateTitle: GuardText {
        if busy { return GuardText("Working") }
        if stale { return GuardText("Guardian unavailable") }
        if legacyPolicy { return GuardText("Restart protection") }
        if isRechecking { return GuardText("Rechecking exit") }
        if status?.phase == "LOCKED" && status?.reason == "underlay-offline" {
            return GuardText("Local network unavailable")
        }
        if status?.phase == "LOCKED" && status?.reason == "settling" {
            return GuardText("Verifying tunnel stability")
        }
        if !active && status?.phase != "ERROR" { return GuardCopy.phase("IDLE") }
        return GuardCopy.phase(status?.phase ?? "IDLE")
    }

    var stateExplanation: GuardText {
        if let notice { return notice }
        if stale { return GuardText("The rule state cannot be confirmed. Use Restore network on this Mac.") }
        if legacyPolicy {
            return GuardText("An earlier policy is active. Close Claude, restore networking locally, then enable the new policy.")
        }
        guard let status else {
            return GuardText("Detect the Shadowrocket tunnel and confirm the node to start a 60-second trial.")
        }
        if status.phase == "IDLE" {
            return status.reason == "trial-ended" ? GuardCopy.reason("trial-ended")
                : GuardText("No whole-device protection rules are active.")
        }
        return GuardCopy.reason(status.reason)
    }

    private func add(_ state: String, _ description: GuardText, ip: String? = nil, at date: Date = Date()) {
        events.insert(GuardEvent(at: date, state: state, text: description.zh, english: description.en, ip: ip), at: 0)
        if events.count > 250 { events.removeLast(events.count - 250) }
        if let encoded = try? JSONEncoder().encode(events) {
            preferences.set(encoded, forKey: "events")
        }
    }

    func detect() {
        guard !checking else { return }
        checking = true
        notice = nil
        Task {
            let current = await Task.detached { LocalCheck.read() }.value
            check = current
            checking = false
            if !active && GuardConfiguration.validInterface(current.defaultInterface) &&
                current.tunnels.contains(current.defaultInterface) {
                configuration.interface = current.defaultInterface
            }
            add("detect", GuardText("Default interface %1$@. Tunnel interfaces found: %2$@.", .plain(current.defaultInterface), .plain(String(current.tunnels.count))))
        }
    }

    func detectEndpoint() {
        guard !active, !busy, !detectingEndpoint else { return }
        let host = configuration.peer
        guard GuardConfiguration.validIPv4(host) else {
            notice = GuardText("Enter the node address before looking for active connections.")
            return
        }
        endpointCandidates = []
        detectingEndpoint = true
        notice = nil
        Task {
            let candidates = await Task.detached { DetectedEndpoint.observe(host: host) }.value
            detectingEndpoint = false
            guard !active, !busy, configuration.peer == host else { return }
            if candidates.count == 1, let endpoint = candidates.first {
                useEndpoint(endpoint)
            } else if candidates.isEmpty {
                notice = GuardText("No Shadowrocket connection to this address was found. Connect the node, open an ordinary webpage, then try again.")
            } else {
                endpointCandidates = candidates
                notice = GuardText("Multiple connections match this node. Select the connection shown in the node details.")
            }
        }
    }

    func importNode() {
        guard !active, !busy else { return }
        guard let text = NSPasteboard.general.string(forType: .string),
              let endpoint = DetectedEndpoint.parseShareLink(text) else {
            notice = GuardText("Copy a supported single-node link from 3x-ui or detect an active connection.")
            return
        }
        let evidence = TransportEvidence.inspect(text, endpoint: endpoint)
        if evidence.kind != .unknown || reviewedTransports[evidence.endpointKey]?.blocksActivation != true {
            reviewedTransports[evidence.endpointKey] = evidence.kind
            if let encoded = try? JSONEncoder().encode(reviewedTransports) {
                preferences.set(encoded, forKey: "reviewedTransports")
            }
        }
        if reviewedTransports[evidence.endpointKey]?.blocksActivation == true {
            notice = GuardText("Use a node link with authenticated encryption and certificate verification enabled.")
            return
        }
        useEndpoint(endpoint)
    }

    func useEndpoint(_ endpoint: DetectedEndpoint) {
        guard !active, !busy else { return }
        configuration.peer = endpoint.host
        configuration.port = String(endpoint.port)
        configuration.transport = endpoint.transport
        endpointCandidates = []
        notice = GuardText("Filled %1$@. Confirm the node and complete a trial.", .plain(endpoint.label))
    }

    func begin(trial: Bool) {
        if !trial && active {
            guard canGoLive else { return }
            busy = true
            notice = nil
            Task {
                let result = await Task.detached { Tools.admin(["continue"], background: false) }.value
                busy = false
                if result.code != 0 { notice = GuardText("Protection was not extended. The current rules are still in place.") }
                refresh()
            }
            return
        }
        guard !active, !busy, trial || canGoLive else { return }
        if currentTransport.blocksActivation {
            notice = GuardText("Use a node link with authenticated encryption and certificate verification enabled.")
            return
        }
        if let problem = configuration.problem { notice = problem; return }
        let cfg = configuration
        let id = UUID().uuidString.lowercased()
        requestSession = id
        pendingAt = nil
        notice = nil
        busy = true
        if let encoded = try? JSONEncoder().encode(cfg) { preferences.set(encoded, forKey: "configuration") }
        let savedService = trial ? nil : approvedRoute?.serviceID
        var workerArgs = ["worker", id, trial ? "trial" : "live", cfg.interface, cfg.peer, cfg.transport, cfg.port, cfg.exit]
        if let savedService { workerArgs.append(savedService) }
        let args = workerArgs
        Task {
            let result = await Task.detached { Tools.admin(args, background: true) }.value
            if result.code != 0 {
                busy = false
                requestSession = nil
                notice = GuardText("Administrator authorization did not complete.")
                add("start-aborted", GuardText("Administrator authorization was not granted."))
            } else {
                pendingAt = Date()
                refresh()
            }
        }
    }

    func restore() {
        guard !busy else { return }
        busy = true
        notice = nil
        Task {
            let result = await Task.detached { Tools.admin(["stop"], background: false) }.value
            busy = false
            refresh()
            if result.code != 0 {
                notice = GuardText("Recovery did not complete. Try again or restart to clear the session rules.")
                add("restore-error", GuardText("The administrator action could not be confirmed."))
            }
        }
    }

    private func refresh() {
        let lock = runtime.appendingPathComponent("active", isDirectory: true).path
        let previousActive = active
        let currentActive = FileManager.default.fileExists(atPath: lock)
        if currentActive != active { active = currentActive }
        let url = runtime.appendingPathComponent("status")
        let incoming = (try? String(contentsOf: url, encoding: .utf8)).flatMap(Snapshot.init)
        if incoming != status { status = incoming }
        let aged = incoming.map { Date().timeIntervalSince($0.time) > 12 } ?? true
        let nextStale = currentActive && aged
        if nextStale != stale { stale = nextStale }
        let left = currentActive ? incoming?.expiration.map { max(0, Int(ceil($0.timeIntervalSinceNow))) } : nil
        if countdown != left { countdown = left }

        if let pendingAt, let requestSession {
            if incoming?.session == requestSession {
                self.pendingAt = nil
                busy = false
            } else if Date().timeIntervalSince(pendingAt) > 10 {
                self.pendingAt = nil
                busy = false
                notice = GuardText("No guardian status was received. Protection is unconfirmed.")
                add("startup-error", GuardText("No status arrived from the local guardian."))
            }
        }
        if currentActive, !aged, let incoming, incoming.mode == "live", incoming.phase == "OPEN",
           incoming.trialVerified, let serviceID = incoming.serviceID,
           incoming.endpointKey == configuration.endpointKey, incoming.expected == configuration.exit {
            let route = ApprovedRoute(endpointKey: configuration.endpointKey, expected: incoming.expected, serviceID: serviceID)
            if route != approvedRoute {
                approvedRoute = route
                if let encoded = try? JSONEncoder().encode(route) { preferences.set(encoded, forKey: "approvedRoute") }
            }
        }
        importJournal()
        sampleTraffic()
        if previousActive && !currentActive && incoming?.phase != "IDLE" {
            add("ended", GuardText("The protection session ended."))
        }
    }

    private func importJournal() {
        let journal = runtime.appendingPathComponent("events")
        guard let text = try? String(contentsOf: journal, encoding: .utf8),
              text != lastJournalText else { return }
        lastJournalText = text
        let lines = text.split(whereSeparator: \.isNewline).map(String.init)
        let start = lastImportedLine.flatMap { lines.lastIndex(of: $0) }.map { $0 + 1 } ?? 0
        for line in lines.dropFirst(start) {
            guard let row = Snapshot(line) else { continue }
            add(row.phase, GuardCopy.reason(row.reason), ip: row.observed == "-" ? nil : row.observed, at: row.time)
        }
        if let last = lines.last {
            lastImportedLine = last
            preferences.set(last, forKey: "lastImportedLine")
        }
    }

    private func sampleTraffic() {
        guard let interface = status?.interface, active, GuardConfiguration.validInterface(interface),
              let current = TunnelCounters.read(interface: interface) else {
            previousCounter = nil
            if rates != nil { rates = nil }
            return
        }
        if let previousCounter, current.uptime - previousCounter.uptime < 1.5 { return }
        let next = previousCounter.flatMap { current.rates(since: $0) }
        previousCounter = current
        if next != rates { rates = next }
    }

    func launch(_ channel: Channel) {
        guard isOpen else { return }
        if let url = channel.webURL {
            NSWorkspace.shared.open(url)
            return
        }
        let path = channel.bundleIDs.compactMap { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) }.first
            ?? channel.paths.map { URL(fileURLWithPath: $0) }.first { FileManager.default.fileExists(atPath: $0.path) }
        guard let path else {
            notice = GuardText("%1$@ is not installed.", .localized(channel.title))
            return
        }
        NSWorkspace.shared.openApplication(at: path, configuration: NSWorkspace.OpenConfiguration()) { _, error in
            if error != nil { Task { @MainActor in self.notice = GuardText("Could not open %1$@.", .localized(channel.title)) } }
        }
    }

    func saveReport(language: GuardLanguage) {
        let dialog = NSSavePanel()
        dialog.allowedContentTypes = [.plainText]
        dialog.nameFieldStringValue = GuardText("Claude Guard Report.txt")[language]
        guard dialog.runModal() == .OK, let url = dialog.url else { return }
        let rows = events.reversed().map { event in
            let exit = event.ip.map { " · " + GuardText("Exit ")[language] + $0 } ?? ""
            return GuardCopy.date(event.at, language) + " · " + GuardCopy.phase(event.state)[language] +
                " · " + event.description(in: language) + exit
        }
        let body = ([
            GuardText("Claude Guard session report")[language],
            GuardCopy.date(Date(), language),
            GuardText("Status ")[language] + stateTitle[language],
            GuardText("Last detection ")[language] + (check?.system ?? "—"),
            GuardText("Approved exit ")[language] + (configuration.exit.isEmpty ? "—" : configuration.exit),
            GuardText("Transport profile ")[language] + currentTransport.title[language],
            GuardText("Evidence scope ")[language] +
                GuardText("The exit is checked through the selected tunnel. Packet contents are not collected.")[language],
            "",
        ] + rows).joined(separator: "\n")
        do { try body.write(to: url, atomically: true, encoding: .utf8) }
        catch { notice = GuardText("Could not write the report. Choose another location."); return }
        notice = GuardText("Report exported.")
    }
}

enum Channel: String, CaseIterable, Identifiable {
    case web, desktop, vscode, terminal
    var id: String { rawValue }
    var title: GuardText {
        switch self {
        case .web: return GuardText("Claude web")
        case .desktop: return GuardText("Claude desktop")
        case .vscode: return GuardText("VS Code")
        case .terminal: return GuardText("Terminal")
        }
    }
    var symbol: String {
        switch self {
        case .web: return "globe"
        case .desktop: return "macwindow"
        case .vscode: return "chevron.left.forwardslash.chevron.right"
        case .terminal: return "terminal"
        }
    }
    var webURL: URL? { self == .web ? URL(string: "https://claude.ai/") : nil }
    var bundleIDs: [String] {
        switch self {
        case .web: return []
        case .desktop: return ["com.anthropic.claudefordesktop"]
        case .vscode: return ["com.microsoft.VSCode"]
        case .terminal: return ["com.apple.Terminal"]
        }
    }
    var paths: [String] {
        switch self {
        case .web: return []
        case .desktop: return ["/Applications/Claude.app"]
        case .vscode: return ["/Applications/Visual Studio Code.app"]
        case .terminal: return ["/System/Applications/Utilities/Terminal.app"]
        }
    }
}
