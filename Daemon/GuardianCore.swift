import Darwin
import Foundation

final class GuardianCore {
    private let store: GuardianStore
    private let recovery: GuardianRecovery?
    private let fence: GuardianPacketFence
    private let powerReady: () -> Bool
    private let queue = DispatchQueue(label: "org.claudeguard.control")
    private var child: Process?
    private var timer: DispatchSourceTimer?
    private var nextRestart: TimeInterval = 0
    private var restartDelay: TimeInterval = 1
    private var lastLaunch: TimeInterval = 0
    private var heartbeatSession: String?
    private var heartbeatStamp: String?
    private var heartbeatObservedAt: TimeInterval?
    private var corruptionSealed = false
    private let workerDirectory = "/var/run/org.claudeguard.runtime"
    private let evaluator = GuardianTrust.directory + "/GuardDaemon"

    init(store: GuardianStore, fence: GuardianPacketFence, recovery: GuardianRecovery? = nil,
         powerReady: @escaping () -> Bool = { false }) {
        self.store = store
        self.fence = fence
        self.recovery = recovery
        self.powerReady = powerReady
    }

    func powerWillSleep() {
        queue.async { _ = self.stopWorker(preserveRules: true) }
    }

    func powerDidWake() {
        queue.async {
            self.nextRestart = 0
            self.restartDelay = 1
            self.supervise()
        }
    }

    func powerFailed() {
        queue.async {
            _ = self.stopWorker(preserveRules: true)
        }
    }

    private func authorized(_ uid: uid_t, form: Data) -> Bool {
        let intentOwner = (try? store.read())?.ownerUID
        return uid == 0 || uid == GuardianTrust.load()?.ownerUID ||
            (intentOwner != 0 && uid == intentOwner) || GuardianAuthorization.validate(form)
    }

    func startSupervision() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now(), repeating: 1)
        timer.setEventHandler { [weak self] in self?.supervise() }
        self.timer = timer
        timer.resume()
    }

    func submit(_ request: GuardianRequest, uid: uid_t, authorization: Data,
                recoveryOnly: Bool, reply: @escaping (GuardianResponse) -> Void) {
        queue.async {
            if request.operation == .restore, let recovery = self.recovery {
                guard self.authorized(uid, form: authorization) else { reply(GuardianResponse(code: 77)); return }
                guard recovery.stopMain() == 0 else { reply(GuardianResponse(code: 74)); return }
            }
            do {
                let response = try self.store.locked {
                    if request.operation == .hello { return GuardianResponse(code: 0) }
                    if recoveryOnly && ![.state, .restore].contains(request.operation) { return GuardianResponse(code: 65) }
                    let installOwner = GuardianTrust.load()?.ownerUID
                    let currentIntent = try? self.store.read()
                    let intentOwner = currentIntent?.ownerUID
                    if request.operation == .state, installOwner == 0, intentOwner == 0,
                       currentIntent?.armed == false, currentIntent?.approved == false,
                       currentIntent?.maintenance == false {
                        var response = GuardianResponse(code: 0)
                        response.automaticEnabled = currentIntent?.automaticEnabled ?? true
                        response.controlRevision = currentIntent?.effectiveControlRevision
                        return response
                    }
                    let authorized = uid == 0 || uid == installOwner ||
                        (intentOwner != 0 && uid == intentOwner) || GuardianAuthorization.validate(authorization)
                    if !authorized { return GuardianResponse(code: 77) }
                    if request.operation == .restore {
                        var intent = GuardianIntent()
                        intent.advanceControlRevision()
                        intent.ownerUID = uid
                        intent.automaticEnabled = false
                        try self.store.write(intent)
                        let result = self.stopWorker(preserveRules: false)
                        if result == 0, self.powerReady() {
                            // An explicit successful restore may repair corrupt
                            // fence metadata. It never clears pending sleep.
                            try self.fence.monitoringReady()
                        }
                        return self.snapshot(intent, code: result)
                    }
                    var intent = try self.store.read()
                    if intent.ownerUID != 0 && intent.ownerUID != uid && uid != 0 && !GuardianAuthorization.validate(authorization) {
                        return GuardianResponse(code: 77)
                    }
                    switch request.operation {
                    case .state:
                        return self.snapshot(intent)
                    case .activate:
                        guard let route = request.route, route.valid,
                              request.profileServer == route.peer,
                              let evidence = request.profileEvidence, evidence.endpointKey == route.endpointKey,
                              !evidence.kind.blocksActivation,
                              let fingerprint = request.profileFingerprint,
                              fingerprint.range(of: #"^[a-f0-9]{64}\z"#, options: .regularExpression) != nil,
                              let session = request.session, UUID(uuidString: session) != nil,
                              let boot = GuardianStore.bootID() else { return GuardianResponse(code: 65) }
                        if intent.armed, intent.route == route, intent.profileFingerprint == fingerprint {
                            guard request.controlRevision == intent.effectiveControlRevision || request.session == intent.session else {
                                return self.snapshot(intent, code: 79)
                            }
                            return self.snapshot(intent)
                        }
                        guard request.controlRevision == intent.effectiveControlRevision,
                              intent.automaticEnabled != false || request.userInitiated == true else {
                            return self.snapshot(intent, code: 79)
                        }
                        guard !(intent.armed && intent.mode == "trial") else { return self.snapshot(intent, code: 82) }
                        guard !(intent.maintenance && intent.approved) else { return self.snapshot(intent, code: 82) }
                        // Persist the sealed transition before stopping a previous worker.
                        if intent.armed || intent.maintenance {
                            intent.advanceControlRevision()
                            intent.armed = false
                            intent.maintenance = true
                            try self.store.write(intent)
                            guard self.stopWorker(preserveRules: true) == 0 else { return self.snapshot(intent, code: 80) }
                        }
                        let previousService = intent.route?.endpointKey == route.endpointKey ? intent.serviceID : nil
                        intent = GuardianIntent()
                        intent.advanceControlRevision()
                        intent.ownerUID = uid
                        intent.armed = true
                        intent.approved = true
                        intent.persistent = true
                        intent.mode = "live"
                        intent.session = session
                        intent.route = route
                        intent.serviceID = previousService
                        intent.bootstrapHost = route.peer
                        intent.bootID = boot
                        intent.profileFingerprint = fingerprint
                        try self.store.write(intent)
                        try self.launch(intent)
                    case .invalidate:
                        guard request.controlRevision == intent.effectiveControlRevision else { return self.snapshot(intent, code: 79) }
                        guard intent.armed || intent.maintenance else { return self.snapshot(intent) }
                        if intent.maintenance && !intent.armed && !intent.approved { return self.snapshot(intent) }
                        intent.advanceControlRevision()
                        intent.armed = false
                        intent.approved = false
                        intent.maintenance = true
                        intent.persistent = true
                        intent.riskKey = nil
                        intent.profileFingerprint = nil
                        intent.trialDeadline = 0
                        intent.mode = "live"
                        intent.session = UUID().uuidString.lowercased()
                        try self.store.write(intent)
                        guard self.stopWorker(preserveRules: true) == 0 else { return self.snapshot(intent, code: 80) }
                        try self.launchSeal(intent)
                    case .trial:
                        if intent.armed && intent.session == request.session {
                            guard request.route == intent.route, request.riskKey == intent.riskKey else { return GuardianResponse(code: 65) }
                            return self.snapshot(intent)
                        }
                        guard !intent.armed, !intent.maintenance, self.knownWorkerPID() == nil,
                              let session = request.session, UUID(uuidString: session) != nil,
                              let route = request.route, route.valid, let link = request.nodeLink, route.matches(link),
                              let key = request.riskKey, GuardRiskPolicy.validKey(key),
                              let bootID = GuardianStore.bootID() else { return GuardianResponse(code: 65) }
                        guard request.controlRevision == intent.effectiveControlRevision, request.userInitiated == true else {
                            return self.snapshot(intent, code: 79)
                        }
                        guard !FileManager.default.fileExists(atPath: "/Library/LaunchDaemons/org.claudeguard.guardian.plist") else {
                            return GuardianResponse(code: 86)
                        }
                        let previousAutomatic = intent.automaticEnabled
                        intent = GuardianIntent()
                        intent.advanceControlRevision()
                        intent.automaticEnabled = previousAutomatic
                        intent.ownerUID = uid
                        intent.armed = true
                        intent.session = session
                        intent.route = route
                        intent.bootstrapHost = route.peer
                        intent.riskKey = key
                        intent.trialDeadline = Int64(Date().timeIntervalSince1970) + 60
                        intent.bootID = bootID
                        try self.store.write(intent)
                        try self.launch(intent)
                    case .commit:
                        let status = self.statusFields()
                        guard intent.armed, request.session == intent.session, intent.mode == "trial", intent.trialDeadline > Int64(Date().timeIntervalSince1970),
                              self.matches(status, intent: intent), ["OPEN", "LOCKED"].contains(status?[1] ?? ""),
                              status?[9] == "1", let service = status?[10], UUID(uuidString: service) != nil else {
                            return GuardianResponse(code: 82)
                        }
                        guard request.controlRevision == intent.effectiveControlRevision, request.userInitiated == true else {
                            return self.snapshot(intent, code: 79)
                        }
                        intent.advanceControlRevision()
                        intent.automaticEnabled = true
                        intent.mode = "live"
                        intent.approved = true
                        intent.persistent = true
                        intent.serviceID = service
                        intent.trialDeadline = 0
                        try self.store.write(intent)
                        let result = self.runControl("continue")
                        if result != 0 { return self.snapshot(intent, code: result) }
                    case .resume:
                        if intent.armed && !intent.maintenance && intent.session == request.session { return self.snapshot(intent) }
                        guard intent.approved, let session = request.session, UUID(uuidString: session) != nil,
                              let bootID = GuardianStore.bootID() else { return GuardianResponse(code: 82) }
                        guard request.controlRevision == intent.effectiveControlRevision, request.userInitiated == true else {
                            return self.snapshot(intent, code: 79)
                        }
                        guard self.stopWorker(preserveRules: true) == 0 else { return self.snapshot(intent, code: 80) }
                        intent.armed = true
                        intent.advanceControlRevision()
                        intent.maintenance = false
                        intent.session = session
                        intent.mode = "live"
                        intent.persistent = true
                        intent.trialDeadline = 0
                        intent.bootID = bootID
                        try self.store.write(intent)
                        try self.launch(intent)
                    case .pause:
                        guard intent.armed, intent.approved else { return GuardianResponse(code: 82) }
                        guard request.controlRevision == intent.effectiveControlRevision, request.userInitiated == true else {
                            return self.snapshot(intent, code: 79)
                        }
                        intent.advanceControlRevision()
                        intent.armed = false
                        intent.maintenance = true
                        intent.session = UUID().uuidString.lowercased()
                        try self.store.write(intent)
                        guard self.stopWorker(preserveRules: true) == 0 else { return self.snapshot(intent, code: 80) }
                        try self.launchSeal(intent)
                    case .hello, .restore: return GuardianResponse(code: 65)
                    }
                    return self.snapshot(intent)
                }
                if request.operation == .restore && response.code == 0 { self.recovery?.restartMain() }
                reply(response)
            } catch {
                reply(GuardianResponse(code: 74))
            }
        }
    }

    func prepareUpgrade() -> Int32 {
        do {
            return try store.locked {
                var intent = try store.read()
                intent.advanceControlRevision()
                if intent.armed || intent.maintenance {
                    intent.armed = false
                    intent.maintenance = true
                    try store.write(intent)
                    return stopWorker(preserveRules: true)
                }
                try store.write(intent)
                return 0
            }
        } catch { return 74 }
    }

    func restoreLocal() -> Int32 {
        let box = GuardianReplyBox()
        submit(GuardianRequest(.restore), uid: 0, authorization: Data(), recoveryOnly: true) { box.finish($0) }
        guard box.semaphore.wait(timeout: .now() + 45) == .success else { return 74 }
        return box.result().code
    }

    private func supervise() {
        do {
            try store.locked {
                var intent = try store.read()
                if intent.armed, let boot = GuardianStore.bootID(), intent.bootID != boot && !intent.persistent && !intent.maintenance {
                    intent.disarm()
                    try store.write(intent)
                }
                if intent.mode == "trial", intent.armed, intent.trialDeadline <= Int64(Date().timeIntervalSince1970) {
                    intent.disarm()
                    try store.write(intent)
                    _ = stopWorker(preserveRules: false)
                    return
                }
                guard intent.armed || intent.maintenance else {
                    if knownWorkerPID() != nil && !corruptionSealed {
                        guard stopWorker(preserveRules: true) == 0 else { return }
                        try launchSeal(nil)
                        corruptionSealed = true
                    } else if knownWorkerPID() == nil { corruptionSealed = false }
                    return
                }
                corruptionSealed = false
                if powerReady(), !fence.isAwake, ProcessInfo.processInfo.systemUptime >= nextRestart {
                    // A transient PF failure can leave a non-sleep emergency
                    // seal after registration remains healthy. Retry metadata
                    // readiness only; pending sleep or a newer revocation must
                    // still require its matching completed-wake callback.
                    try? fence.monitoringReady()
                }
                guard powerReady(), fence.isAwake else {
                    if ProcessInfo.processInfo.systemUptime >= nextRestart {
                        nextRestart = ProcessInfo.processInfo.systemUptime + 5
                        _ = stopWorker(preserveRules: true)
                    }
                    return
                }
                if let session = intent.session, !fence.matchesSession(session) {
                    // Even a short sleep invalidates the previous worker and
                    // its identity dwell, independently of status timestamps.
                    guard stopWorker(preserveRules: true) == 0 else { return }
                    nextRestart = 0
                }
                if intent.armed, intent.serviceID == nil, let fields = statusFields(), matches(fields, intent: intent),
                   UUID(uuidString: fields[10]) != nil {
                    intent.serviceID = fields[10]
                    try store.write(intent)
                }
                if let child, child.isRunning {
                    let fields = statusFields()
                    let fresh = heartbeatFresh(fields, intent: intent)
                    let launchAge = ProcessInfo.processInfo.systemUptime - lastLaunch
                    if fresh || (0...15).contains(launchAge) {
                        if fields?[0] == intent.session && fields?[1] == "OPEN" {
                            restartDelay = 1
                            nextRestart = 0
                        }
                        return
                    }
                    guard stopWorker(preserveRules: true) == 0 else { return }
                }
                guard ProcessInfo.processInfo.systemUptime >= nextRestart else { return }
                if knownWorkerPID() != nil {
                    guard stopWorker(preserveRules: true) == 0 else { return }
                }
                nextRestart = ProcessInfo.processInfo.systemUptime + restartDelay
                restartDelay = min(30, restartDelay * 2)
                intent.session = UUID().uuidString.lowercased()
                try store.write(intent)
                if intent.maintenance { try launchSeal(intent) }
                else { try launch(intent) }
            }
        } catch {
            // Corrupt required state must not become an instruction to release networking.
            try? store.locked {
                if (try? store.read()) != nil { return }
                if corruptionSealed && child?.isRunning == true { return }
                guard stopWorker(preserveRules: true) == 0, ProcessInfo.processInfo.systemUptime >= nextRestart else { return }
                nextRestart = ProcessInfo.processInfo.systemUptime + 30
                guard powerReady(), fence.isAwake else { return }
                try launchSeal(nil)
                corruptionSealed = true
            }
        }
    }

    private func launch(_ intent: GuardianIntent) throws {
        guard let route = intent.route, let session = intent.session,
              intent.valid else { throw GuardianStore.Failure.corrupt }
        let service = intent.serviceID ?? ""
        let boot = service.isEmpty ? "run" : "boot"
        let fields = [intent.mode, route.interface, route.peer, route.transport, route.port,
                      route.expected, route.region, service, boot, String(intent.trialDeadline), route.adminSource,
                      route.developmentPeer ?? ""]
        try launch(session: session, key: intent.riskKey ?? "", fields: fields)
    }

    private func launchSeal(_ intent: GuardianIntent?) throws {
        let route = intent?.route ?? GuardianRoute(interface: "utun0", peer: "127.0.0.1", port: "1",
                                                  transport: "tcp", expected: "127.0.0.1", region: "US", adminSource: "")
        let fields = ["sealed", route.interface, route.peer, route.transport, route.port,
                      route.expected, route.region, intent?.serviceID ?? "", "run", "0", route.adminSource,
                      route.developmentPeer ?? ""]
        try launch(session: intent?.session ?? UUID().uuidString.lowercased(), key: "", fields: fields)
    }

    private func launch(session: String, key: String, fields: [String]) throws {
        guard powerReady(), fence.isAwake else {
            throw GuardianPacketFence.Failure.revoked
        }
        // No previous tunnel-pass rules may outlive their worker when a
        // replacement cannot be spawned. Seal before rotating permission.
        try fence.revokeOpen(forceSeal: true)
        try fence.begin(session, openAllowed: fields.first != "sealed")
        var inputDelivered = false
        defer { if !inputDelivered { try? fence.revokeOpen() } }
        let process = Process()
        let input = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", privilegedWorker, "claude-guard-worker", "worker-input", session]
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/var/empty", "LC_ALL": "C"]
        process.standardInput = input
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        child = process
        lastLaunch = ProcessInfo.processInfo.systemUptime
        heartbeatSession = nil
        heartbeatStamp = nil
        heartbeatObservedAt = nil
        let data = Data((key + "\n" + fields.joined(separator: "|") + "\n" + evaluator + "\n").utf8)
        try input.fileHandleForWriting.write(contentsOf: data)
        try input.fileHandleForWriting.close()
        inputDelivered = true
    }

    private func stopWorker(preserveRules: Bool) -> Int32 {
        do { try fence.revokeOpen() }
        catch {
            do { try fence.inhibit() }
            catch { if preserveRules { return 80 } }
        }
        let ownedChild = child
        if let pid = ownedChild.flatMap({ $0.isRunning ? $0.processIdentifier : nil }) ?? knownWorkerPID() {
            kill(pid, SIGTERM)
            func stillRunning() -> Bool {
                if let ownedChild, ownedChild.processIdentifier == pid { return ownedChild.isRunning }
                return knownWorkerPID() == pid
            }
            let deadline = ProcessInfo.processInfo.systemUptime + 6
            while stillRunning() && ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval: 0.05) }
            if stillRunning() {
                kill(pid, SIGKILL)
                let killDeadline = ProcessInfo.processInfo.systemUptime + 2
                while stillRunning() && ProcessInfo.processInfo.systemUptime < killDeadline { Thread.sleep(forTimeInterval: 0.05) }
            }
            if stillRunning() { return 80 }
        }
        child = nil
        if preserveRules { return 0 }
        do { try fence.clear() }
        catch { return 81 }
        return runControl("stop")
    }

    private func runControl(_ action: String) -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", privilegedWorker, "claude-guard-worker", action]
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/var/empty", "LC_ALL": "C"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run(); return GuardianProcess.wait(process, seconds: 15) }
        catch { return 74 }
    }

    private func knownWorkerPID() -> pid_t? {
        guard let text = boundedFile(workerDirectory + "/active/pid", limit: 32),
              let pid = Int32(text.trimmingCharacters(in: .whitespacesAndNewlines)), pid > 1,
              let session = boundedFile(workerDirectory + "/active/session", limit: 64)?.trimmingCharacters(in: .whitespacesAndNewlines),
              UUID(uuidString: session) != nil else { return nil }
        if let child, child.processIdentifier == pid { return child.isRunning ? pid : nil }
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-ww", "-p", String(pid), "-o", "uid=", "-o", "command="]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return nil }
        let bytes = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let command = String(decoding: bytes, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard process.terminationStatus == 0, command.split(maxSplits: 1, whereSeparator: \.isWhitespace).first == "0",
              command.hasSuffix(" claude-guard-worker worker-input " + session) else { return nil }
        return pid
    }

    private func boundedFile(_ path: String, limit: Int) -> String? {
        let file = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard file >= 0 else { return nil }
        defer { close(file) }
        var metadata = stat()
        guard fstat(file, &metadata) == 0, metadata.st_uid == 0, metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_size <= limit else { return nil }
        let handle = FileHandle(fileDescriptor: file, closeOnDealloc: false)
        guard let bytes = try? handle.read(upToCount: limit + 1), bytes.count <= limit else { return nil }
        return String(data: bytes, encoding: .utf8)
    }

    private func statusFields() -> [String]? {
        guard let text = boundedFile(workerDirectory + "/status", limit: 2048) else { return nil }
        let fields = text.trimmingCharacters(in: .newlines).components(separatedBy: "|")
        return fields.count == 14 ? fields : nil
    }

    private func matches(_ status: [String]?, intent: GuardianIntent) -> Bool {
        guard let status, let stamp = Double(status[2]), (0...12).contains(Date().timeIntervalSince1970 - stamp) else { return false }
        return status[0] == intent.session && status[4] == intent.route?.expected &&
            status[11] == intent.route?.endpointKey && status[12] == GuardianSchema.policy
    }

    private func heartbeatFresh(_ status: [String]?, intent: GuardianIntent) -> Bool {
        guard let status, let session = intent.session, status[0] == session,
              let stamp = Double(status[2]), stamp.isFinite else { return false }
        let now = ProcessInfo.processInfo.systemUptime
        if heartbeatSession != session || heartbeatStamp != status[2] {
            heartbeatSession = session
            heartbeatStamp = status[2]
            heartbeatObservedAt = now
        }
        // Seeing the same publication again does not renew its lifetime, even
        // if wall-clock adjustment makes that timestamp appear recent again.
        guard let observed = heartbeatObservedAt else { return false }
        return matches(status, intent: intent) && (0...12).contains(now - observed)
    }

    private func snapshot(_ intent: GuardianIntent, code: Int32 = 0) -> GuardianResponse {
        var response = GuardianResponse(code: code)
        response.active = intent.armed || intent.maintenance || FileManager.default.fileExists(atPath: workerDirectory + "/active")
        response.persistent = intent.persistent
        response.canResume = intent.approved
        response.paused = intent.maintenance && intent.approved
        response.automaticEnabled = intent.automaticEnabled ?? true
        response.controlRevision = intent.effectiveControlRevision
        response.profileFingerprint = intent.approved ? intent.profileFingerprint : nil
        // This is bootstrap context, not an OPEN authorization. It permits the
        // same node to start fresh root-only checks while apps stay sealed. An
        // unapproved migration can precede service pinning; its root-owned route
        // is still usable for discovery, but cannot resume or authorize OPEN.
        if intent.armed || intent.maintenance, var route = intent.route,
           intent.serviceID.flatMap({ UUID(uuidString: $0) }) != nil ||
            (intent.maintenance && !intent.approved && intent.bootstrapHost == route.peer) {
            if let fields = statusFields(), matches(fields, intent: intent),
               fields[1] == "LOCKED", fields[6] == "exit-mismatch", DetectedEndpoint.validIPv4(fields[5]) {
                route.expected = fields[5]
            }
            response.revalidationRoute = route
        }
        response.workerAlive = knownWorkerPID() != nil
        if let fields = statusFields(), fields[0] == intent.session || (fields[1] == "IDLE" && !intent.armed && !intent.maintenance) {
            if fields[1] != "OPEN" || (matches(fields, intent: intent) && fence.permitsOpen(fields[0])) {
                response.status = fields.joined(separator: "|")
            }
        }
        response.journal = boundedFile(workerDirectory + "/events", limit: 65536)
        return response
    }
}
