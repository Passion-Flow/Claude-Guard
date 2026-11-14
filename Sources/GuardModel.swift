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
    var adminSource: String?
    var approvedRegion: String?
    var developmentPeer: String?

    var developmentAddress: String {
        get { developmentPeer ?? "" }
        set { developmentPeer = newValue.isEmpty ? nil : newValue }
    }

    var adminAddress: String {
        get { adminSource ?? "" }
        set { adminSource = newValue.isEmpty ? nil : newValue }
    }
    var exit: String { expected.isEmpty ? peer : expected }
    var endpointKey: String { peer + ":" + port + "/" + transport }

    static func validIPv4(_ value: String) -> Bool { DetectedEndpoint.validIPv4(value) }

    static func validInterface(_ value: String) -> Bool {
        value.range(of: #"^utun[0-9]+\z"#, options: .regularExpression) != nil
    }

    var problem: GuardText? {
        if !Self.validIPv4(peer) { return GuardText("Enter a valid numeric node address.") }
        if ["1.1.1.1", "1.0.0.1"].contains(peer) { return GuardText("The node address must be different from both health probes.") }
        if !Self.validIPv4(exit) { return GuardText("Enter a valid numeric exit address.") }
        if !GuardRiskPolicy.regions.contains(approvedRegion ?? "") { return GuardText("Select the approved exit region.") }
        if let developmentPeer, !GuardianRoute.validDevelopmentPeer(developmentPeer) {
            return GuardText("Use a single Tailscale IPv4 peer address, or leave it empty.")
        }
        if let value = UInt16(port), value > 0, String(value) == port { }
        else { return GuardText("Enter the node port (1–65535).") }
        if !["tcp", "udp"].contains(transport) { return GuardText("Select the node transport.") }
        if !adminAddress.isEmpty && !Self.validIPv4(adminAddress) {
            return GuardText("Enter a valid numeric admin address, or leave it empty.")
        }
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
    let riskCheckedAt: Date?

    init?(_ line: String) {
        let fields = line.trimmingCharacters(in: .newlines).split(separator: "|", omittingEmptySubsequences: false)
        guard (9...14).contains(fields.count), let stamp = Double(fields[2]), stamp.isFinite,
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
        riskCheckedAt = fields.count >= 14 ? Double(fields[13]).flatMap { $0 > 0 && $0.isFinite ? Date(timeIntervalSince1970: $0) : nil } : nil
    }
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
            .split(whereSeparator: \.isNewline).contains { $0.contains("(Connected)") && $0.hasSuffix("[VPN:com.liguangming.Shadowrocket]") }
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


}

@MainActor
final class GuardController: ObservableObject {
    let browserDiagnostics = BrowserDiagnostics()
    let serviceDiagnostics = ServiceDiagnostics()
    private let shadowrocketStartup = ShadowrocketStartup()
    @Published var configuration: GuardConfiguration
    @Published private(set) var check: LocalCheck?
    @Published private(set) var status: Snapshot?
    @Published private(set) var events: [GuardEvent] = []
    @Published private(set) var busy = false
    @Published private(set) var checking = false
    @Published private(set) var detectingEndpoint = false
    @Published private(set) var endpointCandidates: [DetectedEndpoint] = []
    @Published private(set) var active = false
    @Published private(set) var stale = false
    @Published private(set) var countdown: Int?
    @Published var notice: GuardText?
    @Published private var reviewedTransports: [String: TransportEvidence.Kind] = [:]
    @Published private(set) var rates: TunnelRates?
    @Published private(set) var persistent = false
    @Published private(set) var serviceAvailable = false
    @Published private(set) var canResumeSaved = false
    @Published private(set) var paused = false
    @Published var riskKey = ""
    @Published private(set) var automaticEnabled = true
    @Published private(set) var automaticChecking = false
    private var nextAutomaticCheck = Date.distantPast
    private var automaticGeneration = 0
    private var automaticFingerprint: String?
    private var requestedProfileAccess = false
    private var automaticIssue: AutomaticSetupIssue?
    private var controlRevision: String?
    private var revalidationRoute: GuardianRoute?
    #if GUARD_DIAGNOSTICS
    private var diagnosticAutomaticAttempts = 0
    #endif

    private var lastImportedLine: String?
    private var lastJournalText: String?
    private var requestSession: String?
    private var pendingAt: Date?
    private var timer: Timer?
    private var previousCounter: TunnelCounters?
    private var pollingService = false
    private var reviewedNodeLink: String?
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
            let demo = "demo|OPEN|" + String(Date().timeIntervalSince1970) + "|utun6|-|-|stable-open|0|live|1|||" + GuardPolicy.id + "|" + String(Date().timeIntervalSince1970)
            status = Snapshot(demo)
            reviewedTransports = [configuration.endpointKey: .reality]
            rates = TunnelRates(received: 126000, sent: 18400)
            active = true
            serviceAvailable = true
            persistent = true
            canResumeSaved = true
            return
        }
        if let data = preferences.data(forKey: "configuration"),
           let saved = try? JSONDecoder().decode(GuardConfiguration.self, from: data) {
            configuration = saved
        } else { configuration = GuardConfiguration() }
        configuration.adminSource = nil
        if let data = preferences.data(forKey: "events"),
           let saved = try? JSONDecoder().decode([GuardEvent].self, from: data) {
            events = saved
        } else { events = [] }
        preferences.removeObject(forKey: "approvedRoute")
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
        guard serviceAvailable, !stale, !busy, !detectingEndpoint else { return false }
        if paused { return canResumeSaved }
        if !active {
            return canResumeSaved
        }
        guard let status, !stale, !legacyPolicy, status.trialVerified else { return false }
        return status.mode == "trial" && !["ERROR", "DRIFT"].contains(status.phase)
    }
    var legacyPolicy: Bool {
        active && status.map { ["OPEN", "LOCKED"].contains($0.phase) && $0.policyID != GuardPolicy.id } == true
    }

    var rulesConfirmed: Bool {
        active && !stale && !legacyPolicy && status.map { ["OPEN", "LOCKED"].contains($0.phase) } == true
    }

    var isOpen: Bool {
        rulesConfirmed && status?.phase == "OPEN" && status?.riskCheckedAt.map {
            (0..<3600).contains(Date().timeIntervalSince($0))
        } == true
    }
    var isRechecking: Bool { status?.reason == "probe-retry" && active && !stale }
    var mayRestore: Bool { (active || persistent || canResumeSaved || paused) && !busy }
    var mayPause: Bool { active && !paused && status?.mode == "live" && !busy }

    var riskStatus: GuardText {
        if status?.reason == "risk-refresh-pending" { return GuardText("Risk refresh pending") }
        if status?.reason == "risk-review" { return GuardText("Risk check in progress") }
        if isOpen { return GuardText("Risk check passed") }
        switch status?.reason {
        case "risk-review": return GuardText("Risk check in progress")
        case "risk-rejected": return GuardText("Risk policy denied release")
        case "risk-rate-limited", "risk-query-budget": return GuardText("Risk check deferred")
        default: return GuardText("Risk evidence unavailable")
        }
    }

    func openRecovery() {
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.arguments = ["--recovery"]
        configuration.createsNewApplicationInstance = true
        NSWorkspace.shared.openApplication(at: Bundle.main.bundleURL, configuration: configuration) { _, _ in }
    }
    var currentTransport: TransportEvidence.Kind {
        reviewedTransports[configuration.endpointKey] ?? .unknown
    }

    var stateTitle: GuardText {
        if busy { return GuardText("Working") }
        if !serviceAvailable && !preview { return GuardText("Install the system guardian") }
        if paused { return GuardText("Protection paused") }
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
        if !serviceAvailable && !preview { return GuardText("Open the private installer to install the system guardian. macOS asks for administrator authorization.") }
        if stale { return GuardText("The rule state cannot be confirmed. Use Restore network on this Mac.") }
        if legacyPolicy {
            return GuardText("An earlier policy is active. Close your apps, restore networking locally, then enable the new policy.")
        }
        if !active && !automaticEnabled {
            return GuardText("Automatic protection is disabled. Enable it to resume detection and enforcement.")
        }
        guard let status else {
            return GuardText("Shadowrocket is checked automatically. Apps are released only after tunnel stability and risk checks pass.")
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

    func openBrowserDiagnostics(language: GuardLanguage, appearance: GuardAppearance) {
        guard isOpen, !busy, let status, status.mode == "live" else { return }
        browserDiagnostics.start(status, language: language, appearance: appearance)
    }

    func openDiagnosticSite(_ site: ExternalDiagnosticSite) {
        guard isOpen, !busy, status?.mode == "live" else { return }
        NSWorkspace.shared.open(site.url)
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
        reviewedTransports[evidence.endpointKey] = evidence.kind
        if let encoded = try? JSONEncoder().encode(reviewedTransports) {
            preferences.set(encoded, forKey: "reviewedTransports")
        }
        if evidence.kind.blocksActivation {
            notice = GuardText("Use a node link with authenticated encryption and certificate verification enabled.")
            return
        }
        reviewedNodeLink = text
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

    func retryAutomaticSetup() {
        // Only an explicit operator retry may reopen the native access dialog.
        // A failed bookmark must not create an unattended prompt loop.
        requestedProfileAccess = false
        automaticGeneration += 1
        automaticCheck(force: true)
    }

    private func completeProfileAccess(granted: Bool, generation: Int, userInitiated: Bool) {
        guard granted, generation == automaticGeneration, !paused, userInitiated || automaticEnabled else { return }
        automaticCheck(force: userInitiated)
    }

    private func clearRecoveredAutomaticIssue() {
        if let issue = automaticIssue, notice == issue.message { notice = nil }
        automaticIssue = nil
    }

    #if GUARD_DIAGNOSTICS
    static func automaticIssueLifecycleSelfTest() -> Bool {
        let controller = GuardController(preview: true)
        controller.automaticIssue = .probeResponse
        controller.notice = AutomaticSetupIssue.probeResponse.message
        guard controller.report(language: .english).contains("probeResponse") else { return false }
        controller.clearRecoveredAutomaticIssue()
        guard controller.notice == nil, controller.automaticIssue == nil,
              !controller.report(language: .english).contains("probeResponse") else { return false }
        controller.automaticIssue = .disconnected
        controller.notice = GuardText("Report exported.")
        controller.clearRecoveredAutomaticIssue()
        guard controller.automaticIssue == nil && controller.notice == GuardText("Report exported.") else { return false }
        // An unrelated action message must not conceal current policy evidence
        // or a lost guardian. The view displays that message separately.
        guard let status = controller.status,
              controller.stateExplanation == GuardCopy.reason(status.reason) else { return false }
        let now = String(Date().timeIntervalSince1970)
        controller.status = Snapshot("demo|OPEN|" + now + "|utun6|-|-|probe-retry|0|live|1|||" + GuardPolicy.id + "|" + now)
        guard controller.isRechecking, controller.isOpen,
              controller.riskStatus == GuardText("Risk check passed") else { return false }
        controller.status = status
        controller.stale = true
        guard controller.stateExplanation == GuardText("The rule state cannot be confirmed. Use Restore network on this Mac.") else { return false }
        controller.stale = false
        controller.automaticGeneration = 0
        controller.automaticEnabled = true
        controller.active = false
        let oldGeneration = controller.automaticGeneration
        let oldRevision = UUID().uuidString.lowercased()
        controller.controlRevision = oldRevision
        var restored = GuardianResponse(code: 0)
        restored.automaticEnabled = false
        restored.controlRevision = UUID().uuidString.lowercased()
        controller.applyServiceState(restored)
        var oldState = GuardianResponse(code: 0)
        oldState.controlRevision = oldRevision
        controller.finishPoll(oldState, generation: oldGeneration)
        guard !controller.automaticEnabled, controller.controlRevision == restored.controlRevision else { return false }
        controller.completeProfileAccess(granted: true, generation: oldGeneration, userInitiated: false)
        controller.completeProfileAccess(granted: true, generation: oldGeneration, userInitiated: true)
        controller.completeProfileAccess(granted: true, generation: controller.automaticGeneration, userInitiated: false)
        guard controller.diagnosticAutomaticAttempts == 0 else { return false }
        controller.completeProfileAccess(granted: true, generation: controller.automaticGeneration, userInitiated: true)
        return controller.diagnosticAutomaticAttempts == 1
    }
    #endif

    func automaticCheck(force: Bool = false) {
        #if GUARD_DIAGNOSTICS
        if preview { diagnosticAutomaticAttempts += 1; return }
        #endif
        guard !preview, serviceAvailable, !busy, !automaticChecking, !paused,
              !(active && status?.mode == "trial"),
              force || automaticEnabled, force || Date() >= nextAutomaticCheck else { return }
        guard let revision = controlRevision else { return }
        automaticChecking = true
        nextAutomaticCheck = Date().addingTimeInterval(30)
        let generation = automaticGeneration
        let region = configuration.approvedRegion ?? "US"
        let fingerprint = automaticFingerprint
        let currentActive = active
        let rediscover = force || status?.reason == "exit-mismatch"
        let revalidation = revalidationRoute
        Task { [self] in
            do {
                let observation = try await Task.detached { () -> (AutomaticRoute?, ShadowrocketProfile?) in
                    if currentActive, !rediscover, let fingerprint {
                        let profile = try ShadowrocketAccess.readCurrent()
                        if profile.fingerprint == fingerprint { return (nil, profile) }
                    }
                    return (try AutomaticRoute.read(region: region, revalidation: revalidation), nil)
                }.value
                defer { automaticChecking = false }
                guard generation == automaticGeneration, !paused, (force || automaticEnabled) else { return }
                if let profile = observation.1 ?? observation.0?.profile {
                    await shadowrocketStartup.prepare(profile: profile, route: revalidation,
                        fingerprint: fingerprint, active: currentActive, persistent: persistent,
                        automatic: automaticEnabled, paused: paused, open: isOpen) { [weak self] in
                            guard let self else { return false }
                            return generation == self.automaticGeneration && self.active && self.persistent &&
                                self.automaticEnabled && !self.paused && !self.isOpen &&
                                self.automaticFingerprint == profile.fingerprint
                        }
                    guard generation == automaticGeneration, !paused, (force || automaticEnabled) else { return }
                }
                if let profile = observation.1, let route = revalidation,
                   route.peer == profile.host, route.port == String(profile.port), route.transport == profile.transport {
                    // Refresh display metadata after an app restart without
                    // submitting activation or rotating a healthy root session.
                    configuration = GuardConfiguration(peer: route.peer, port: route.port,
                        transport: route.transport, expected: route.expected, interface: route.interface,
                        approvedRegion: route.region)
                    reviewedTransports[route.endpointKey] = profile.security
                }
                let result = observation.0
                guard let result else {
                    if isOpen { clearRecoveredAutomaticIssue() }
                    return
                }
                configuration = GuardConfiguration(peer: result.route.peer, port: result.route.port,
                    transport: result.route.transport, expected: result.route.expected, interface: result.route.interface,
                    approvedRegion: region)
                reviewedTransports[configuration.endpointKey] = result.profile.security
                let request = GuardianRequest(.activate, session: UUID().uuidString.lowercased(), route: result.route,
                    profileEvidence: TransportEvidence(endpointKey: result.route.endpointKey, kind: result.profile.security),
                    profileFingerprint: result.profile.fingerprint, profileServer: result.profile.host,
                    controlRevision: revision, userInitiated: force)
                busy = true
                let response = await Task.detached { GuardianClient.send(request) }.value
                busy = false
                guard generation == automaticGeneration else { refresh(); return }
                applyServiceState(response)
                if response.code == 0 {
                    automaticFingerprint = result.profile.fingerprint
                    automaticIssue = nil
                    notice = nil
                } else if force || response.code != 79 { notice = serviceError(response.code) }
            } catch {
                automaticChecking = false
                guard generation == automaticGeneration else { return }
                let issue = AutomaticSetupIssue(error)
                automaticIssue = issue
                if error is ShadowrocketProfile.Failure, active, !paused {
                    busy = true
                    let revoked = await Task.detached { GuardianClient.send(GuardianRequest(.invalidate, controlRevision: revision)) }.value
                    busy = false
                    guard generation == automaticGeneration else { refresh(); return }
                    automaticFingerprint = nil
                    applyServiceState(revoked)
                    guard revoked.code == 0, revoked.active, !revoked.canResume, !revoked.paused else {
                        if force || revoked.code != 79 { notice = serviceError(revoked.code) }
                        return
                    }
                }
                automaticIssue = issue
                let continuationGeneration = automaticGeneration
                if let failure = error as? ShadowrocketProfile.Failure, failure == .unavailable, !requestedProfileAccess {
                    requestedProfileAccess = true
                    let language = GuardLanguage(rawValue: GuardPolicy.preferences.string(forKey: "language") ?? "") ?? .initial
                    ShadowrocketAccess.requestReadAccess(language: language) { [weak self] granted in
                        self?.completeProfileAccess(granted: granted, generation: continuationGeneration, userInitiated: force)
                    }
                }
                notice = issue.message
            }
        }
    }

    func begin(trial: Bool) {
        guard let revision = controlRevision else { return }
        if !trial && active && !paused {
            guard canGoLive, let session = status?.session else { return }
            busy = true
            automaticGeneration += 1
            notice = nil
            Task {
                let response = await Task.detached { GuardianClient.send(GuardianRequest(.commit, session: session,
                    controlRevision: revision, userInitiated: true)) }.value
                busy = false
                applyServiceState(response)
                if response.code != 0 { notice = serviceError(response.code) }
                else { riskKey = ""; reviewedNodeLink = nil }
            }
            return
        }
        guard serviceAvailable, !busy, !active || paused, trial || canGoLive else { return }
        var route: GuardianRoute?
        var key: String?
        var link: String?
        if trial {
            if let problem = configuration.problem { notice = problem; return }
            guard let reviewedNodeLink, let endpoint = DetectedEndpoint.parseShareLink(reviewedNodeLink),
                  endpoint.id == configuration.endpointKey else {
                notice = GuardText("Import a node link again before starting a new trial.")
                return
            }
            guard GuardRiskPolicy.validKey(riskKey) else {
                notice = GuardText("Enter an authorized risk-service key.")
                return
            }
            let cfg = configuration
            route = GuardianRoute(interface: cfg.interface, peer: cfg.peer, port: cfg.port,
                                  transport: cfg.transport, expected: cfg.exit,
                                  region: cfg.approvedRegion ?? "", adminSource: cfg.adminAddress,
                                  developmentPeer: cfg.developmentPeer)
            key = riskKey
            link = reviewedNodeLink
        }
        let id = UUID().uuidString.lowercased()
        let request = GuardianRequest(trial ? .trial : .resume, session: id, route: route, riskKey: key, nodeLink: link,
                                      controlRevision: revision, userInitiated: true)
        automaticGeneration += 1
        requestSession = id
        pendingAt = nil
        notice = nil
        busy = true
        if let encoded = try? JSONEncoder().encode(configuration) { preferences.set(encoded, forKey: "configuration") }
        Task {
            let response = await Task.detached { GuardianClient.send(request) }.value
            if response.code != 0 {
                busy = false
                requestSession = nil
                notice = serviceError(response.code)
                add("start-aborted", GuardText("The guardian did not confirm activation."))
            } else {
                pendingAt = Date()
            }
            applyServiceState(response)
        }
    }

    func pauseProtection() {
        guard mayPause, let revision = controlRevision else { return }
        automaticGeneration += 1
        browserDiagnostics.stop()
        serviceDiagnostics.stop()
        busy = true
        Task {
            let response = await Task.detached { GuardianClient.send(GuardianRequest(.pause, controlRevision: revision, userInitiated: true)) }.value
            busy = false
            applyServiceState(response)
            if response.code != 0 { notice = serviceError(response.code) }
        }
    }

    private func serviceError(_ code: Int32) -> GuardText {
        switch code {
        case 79: return GuardText("Guardian settings changed during this operation. Check the current status and try again.")
        case 78: return GuardText("Install the matching private application and system guardian package.")
        case 77: return GuardText("Administrator authorization did not complete.")
        case 86: return GuardText("Restore the earlier version before installing this guardian.")
        case 65: return GuardText("The guardian rejected the route, node declaration or risk key.")
        default: return GuardText("The guardian did not confirm this operation. Check status before retrying.")
        }
    }

    func restore() {
        guard !busy else { return }
        automaticGeneration += 1
        automaticEnabled = false
        browserDiagnostics.stop()
        serviceDiagnostics.stop()
        busy = true
        notice = nil
        Task {
            let result = await Task.detached { GuardianClient.send(GuardianRequest(.restore)) }.value
            busy = false
            applyServiceState(result)
            refresh()
            if result.code != 0 {
                notice = GuardText("Recovery did not complete. Try again or restart to clear the session rules.")
                add("restore-error", GuardText("The administrator action could not be confirmed."))
            }
        }
    }


    private func refresh() {
        guard !preview, !pollingService else { return }
        pollingService = true
        let generation = automaticGeneration
        Task {
            let response = await Task.detached { GuardianClient.send(GuardianRequest(.state)) }.value
            finishPoll(response, generation: generation)
        }
    }

    private func finishPoll(_ response: GuardianResponse, generation: Int) {
        pollingService = false
        guard generation == automaticGeneration else { return }
        applyServiceState(response)
    }

    private func applyServiceState(_ response: GuardianResponse) {
        let previousActive = active
        let knownState = [0, 79].contains(response.code) && response.controlRevision.flatMap(UUID.init(uuidString:)) != nil
        if knownState {
            if controlRevision != response.controlRevision {
                automaticGeneration += 1
                clearRecoveredAutomaticIssue()
                controlRevision = response.controlRevision
            }
            automaticFingerprint = response.profileFingerprint
            revalidationRoute = response.revalidationRoute
            active = response.active
            persistent = response.persistent
            canResumeSaved = response.canResume
            paused = response.paused
            automaticEnabled = response.automaticEnabled
            serviceAvailable = true
        } else if response.code == 78 {
            serviceAvailable = false
        } else {
            serviceAvailable = true
        }
        let incoming = response.status.flatMap(Snapshot.init)
        if incoming != status { status = incoming }
        let timely = incoming.map { (0...12).contains(Date().timeIntervalSince($0.time)) } ?? false
        let nextStale = !knownState || (active && (!timely || !response.workerAlive))
        if nextStale != stale { stale = nextStale }
        browserDiagnostics.synchronize(incoming, confirmed: rulesConfirmed)
        serviceDiagnostics.synchronize(incoming, confirmed: isOpen)
        let left = active ? incoming?.expiration.map { max(0, Int(ceil($0.timeIntervalSinceNow))) } : nil
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
        if knownState, !active, automaticEnabled { automaticCheck() }
        else if knownState, active, !paused { automaticCheck() }
        importJournal(response.journal)
        sampleTraffic()
        if previousActive && !active && incoming?.phase != "IDLE" {
            add("ended", GuardText("The protection session ended."))
        }
    }

    private func importJournal(_ journal: String?) {
        guard let text = journal,
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

    func saveReport(language: GuardLanguage) {
        let dialog = NSSavePanel()
        dialog.allowedContentTypes = [.plainText]
        dialog.nameFieldStringValue = GuardText("Claude Guard Report.txt")[language]
        guard dialog.runModal() == .OK, let url = dialog.url else { return }
        do { try report(language: language).write(to: url, atomically: true, encoding: .utf8) }
        catch { notice = GuardText("Could not write the report. Choose another location."); return }
        notice = GuardText("Report exported.")
    }

    func report(language: GuardLanguage) -> String {
        let rows = events.reversed().map { event in
            return GuardCopy.date(event.at, language) + " · " + GuardCopy.phase(event.state)[language] +
                " · " + event.description(in: language)
        }
        let browserRows = browserDiagnostics.evidence.map {
            [GuardText("Browser network check")[language] + " · " + $0.summary[language],
             GuardCopy.date($0.checkedAt, language) + " · " + GuardCopy.phase($0.observation.phase)[language],
             GuardText("Browser test scope")[language]]
        } ?? []
        let serviceRows = serviceDiagnostics.results.isEmpty ? [] :
            [GuardText("Anonymous service path")[language], GuardText("Service path scope")[language]] +
            serviceDiagnostics.results.map { $0.id + " · " + $0.outcome.title[language] }
        return ([
            GuardText("Claude Guard session report")[language],
            "v" + GuardPolicy.version,
            GuardCopy.date(Date(), language),
            GuardText("Status ")[language] + stateTitle[language],
            GuardText("Last detection ")[language] + (check?.system ?? "—"),
            GuardText("Automatic setup")[language] + " · " + (automaticIssue.map {
                $0.rawValue + " · " + $0.message[language]
            } ?? "—"),
            GuardText("Transport profile ")[language] + currentTransport.title[language],
            GuardText("Risk admission")[language] + " · " + riskStatus[language],
            GuardText("Last risk check")[language] + " · " + (status?.riskCheckedAt.map { GuardCopy.date($0, language) } ?? "—"),
            GuardText("The approved region, residential classification, low score and clear risk flags are required. Missing or expired evidence keeps apps blocked.")[language],
            GuardText("Evidence scope ")[language] +
                GuardText("The exit is checked through the selected tunnel. Packet contents are not collected.")[language],
            "",
        ] + serviceRows + browserRows + rows).joined(separator: "\n")
    }
}
