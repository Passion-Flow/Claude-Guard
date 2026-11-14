import Darwin
import Foundation

/// Serializes filter writers independently of the control queue. A power event
/// can revoke a worker session without waiting for queued XPC operations.
final class GuardianPacketFence {
    enum Failure: Error { case permission, corrupt, busy, io, revoked, command, readback }
    enum Phase: String { case open = "OPEN", locked = "LOCKED", sealed = "SEALED" }

    private struct Revocation: Codable {
        let id: String
        let boot: String
        let sleepPending: Bool
    }

    private struct State: Codable {
        var version = 1
        var boot: String
        var monitoring = false
        var powerBlocked = true
        var sleepPending = false
        var session: String?
        var clearedSession: String?
        var revocation: String?
        var pfToken: String?
        var openAllowed = false
        var lastRules: String?

        var valid: Bool {
            version == 1 && UUID(uuidString: boot) != nil &&
                (session == nil || UUID(uuidString: session!) != nil) &&
                (clearedSession == nil || UUID(uuidString: clearedSession!) != nil) &&
                (revocation == nil || UUID(uuidString: revocation!) != nil) &&
                (pfToken == nil || pfToken!.range(of: #"^[0-9]{1,20}\z"#, options: .regularExpression) != nil) &&
                (!sleepPending || powerBlocked) &&
                (lastRules == nil || (lastRules!.utf8.count <= 32768 && !lastRules!.contains("\0"))) &&
                (!openAllowed || (session != nil && monitoring && !powerBlocked))
        }
    }

    private let directory: String
    private let owner: uid_t
    private let pf: String
    private let legacyRuntime: String?
    private let descriptor: Int32
    private let signalDescriptor: Int32
    private let localLock = NSLock()
    private let signalLock = NSLock()
    private var commandDeadline: TimeInterval = 0
    private let anchor: String
    private let emergency = "block drop quick all label \"CG_BLOCK\"\n"

    convenience init() throws {
        guard geteuid() == 0 else { throw Failure.permission }
        try self.init(directory: GuardianSchema.stateDirectory, owner: 0, pf: "/sbin/pfctl",
                      legacyRuntime: "/var/run/org.claudeguard.runtime")
    }

    private init(directory: String, owner: uid_t, pf: String, legacyRuntime: String? = nil,
                 anchor: String = "com.apple/00000.org.claudeguard.runtime") throws {
        self.directory = directory
        self.owner = owner
        self.pf = pf
        self.legacyRuntime = legacyRuntime
        self.anchor = anchor
        var metadata = stat()
        guard lstat(directory, &metadata) == 0, metadata.st_uid == owner,
              metadata.st_mode & S_IFMT == S_IFDIR, metadata.st_mode & 0o777 == 0o700 else { throw Failure.permission }
        let fd = open(directory + "/filter.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw Failure.io }
        guard fstat(fd, &metadata) == 0, metadata.st_uid == owner,
              metadata.st_mode & S_IFMT == S_IFREG, metadata.st_mode & 0o777 == 0o600 else {
            close(fd)
            throw Failure.permission
        }
        descriptor = fd
        let signal = open(directory + "/filter-signal.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard signal >= 0 else { close(fd); throw Failure.io }
        guard fstat(signal, &metadata) == 0, metadata.st_uid == owner,
              metadata.st_mode & S_IFMT == S_IFREG, metadata.st_mode & 0o777 == 0o600 else {
            close(signal); close(fd)
            throw Failure.permission
        }
        signalDescriptor = signal
    }

    deinit { close(signalDescriptor); close(descriptor) }

    // This small lock covers only revocation publication/removal, never PF
    // commands or the writer lock. A pending power event closes admission
    // before waiting for the one already-admitted writer to drain.
    private func signaled<T>(_ operation: () throws -> T) throws -> T {
        let until = ProcessInfo.processInfo.systemUptime + 1
        while !signalLock.try() {
            guard ProcessInfo.processInfo.systemUptime < until else { throw Failure.busy }
            Thread.sleep(forTimeInterval: 0.005)
        }
        defer { signalLock.unlock() }
        while flock(signalDescriptor, LOCK_EX | LOCK_NB) != 0 {
            guard [EWOULDBLOCK, EAGAIN, EINTR].contains(errno) else { throw Failure.io }
            guard ProcessInfo.processInfo.systemUptime < until else { throw Failure.busy }
            Thread.sleep(forTimeInterval: 0.005)
        }
        defer { flock(signalDescriptor, LOCK_UN) }
        return try operation()
    }

    private func locked<T>(_ operation: () throws -> T) throws -> T {
        // Acquisition outlasts the complete writer budget, rather than just a
        // single PF subprocess. The power callback can drain an admitted writer
        // and perform its own bounded seal within the OS notification window.
        let until = ProcessInfo.processInfo.systemUptime + 12
        while !localLock.try() {
            guard ProcessInfo.processInfo.systemUptime < until else { throw Failure.busy }
            Thread.sleep(forTimeInterval: 0.01)
        }
        defer { localLock.unlock() }
        while flock(descriptor, LOCK_EX | LOCK_NB) != 0 {
            guard [EWOULDBLOCK, EAGAIN, EINTR].contains(errno) else { throw Failure.io }
            guard ProcessInfo.processInfo.systemUptime < until else { throw Failure.busy }
            Thread.sleep(forTimeInterval: 0.01)
        }
        defer { flock(descriptor, LOCK_UN) }
        commandDeadline = ProcessInfo.processInfo.systemUptime + 8
        defer { commandDeadline = 0 }
        return try operation()
    }

    private func bytes(_ path: String, maximum: Int) throws -> Data? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw Failure.io
        }
        defer { close(fd) }
        var metadata = stat()
        guard fstat(fd, &metadata) == 0, metadata.st_uid == owner,
              metadata.st_mode & S_IFMT == S_IFREG, metadata.st_mode & 0o777 == 0o600,
              metadata.st_size >= 0, metadata.st_size <= off_t(maximum) else { throw Failure.permission }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        guard let data = try handle.read(upToCount: maximum + 1), data.count <= maximum else { throw Failure.corrupt }
        return data
    }

    private func state() throws -> State {
        guard let boot = GuardianStore.bootID() else { throw Failure.io }
        guard let data = try bytes(directory + "/filter.json", maximum: 131072) else { return State(boot: boot) }
        guard let value = try? JSONDecoder().decode(State.self, from: data), value.valid else { throw Failure.corrupt }
        if value.boot != boot {
            var next = State(boot: boot)
            next.lastRules = value.lastRules
            return next
        }
        return value
    }

    private func save(_ value: State) throws {
        guard value.valid else { throw Failure.corrupt }
        let data = try JSONEncoder().encode(value)
        guard data.count <= 131072 else { throw Failure.corrupt }
        try persist(data, name: "filter.json")
    }

    private func persist(_ data: Data, name: String) throws {
        let path = directory + "/" + name
        let temporary = directory + "/filter." + UUID().uuidString + ".tmp"
        let fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw Failure.io }
        defer { close(fd); unlink(temporary) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        try handle.write(contentsOf: data)
        guard fsync(fd) == 0, rename(temporary, path) == 0 else { throw Failure.io }
        let parent = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard parent >= 0 else { throw Failure.io }
        defer { close(parent) }
        guard fsync(parent) == 0 else { throw Failure.io }
    }

    private func revocation() throws -> Revocation? {
        guard let data = try bytes(directory + "/filter-revocation", maximum: 512) else { return nil }
        guard let value = try? JSONDecoder().decode(Revocation.self, from: data),
              UUID(uuidString: value.id) != nil, UUID(uuidString: value.boot) != nil else { throw Failure.corrupt }
        return value
    }

    private func publishRevocation(forSleep: Bool) throws -> Revocation {
        try signaled {
            guard let boot = GuardianStore.bootID() else { throw Failure.io }
            let prior = try revocation()
            let value = Revocation(id: UUID().uuidString, boot: boot,
                sleepPending: forSleep || (prior?.boot == boot && prior?.sleepPending == true))
            try persist(JSONEncoder().encode(value), name: "filter-revocation")
            return value
        }
    }

    // File-backed command I/O cannot wedge the power callback on a full pipe.
    // The filter lock remains held until the direct PF writer has exited.
    private func command(_ arguments: [String], input: Data = Data(), diagnostics: Bool = false) throws -> String {
        guard commandDeadline > ProcessInfo.processInfo.systemUptime else { throw Failure.command }
        let stem = directory + "/filter-command." + UUID().uuidString
        let inputPath = stem + ".in", outputPath = stem + ".out"
        let source = open(inputPath, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard source >= 0 else { throw Failure.io }
        defer { close(source); unlink(inputPath) }
        let target = open(outputPath, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard target >= 0 else { throw Failure.io }
        defer { close(target); unlink(outputPath) }
        let reader = FileHandle(fileDescriptor: source, closeOnDealloc: false)
        let writer = FileHandle(fileDescriptor: target, closeOnDealloc: false)
        try reader.write(contentsOf: input)
        try reader.seek(toOffset: 0)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: pf)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/var/empty", "LC_ALL": "C"]
        process.standardInput = reader
        process.standardOutput = writer
        // The PF child must retain the same open-file-description lock if its
        // parent dies. Passing it as stderr survives spawn's descriptor cleanup.
        // Rewind the private lock file so diagnostics cannot grow per command.
        guard ftruncate(descriptor, 0) == 0, lseek(descriptor, 0, SEEK_SET) == 0 else { throw Failure.io }
        process.standardError = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        let remaining = commandDeadline - ProcessInfo.processInfo.systemUptime
        guard remaining > 0 else { throw Failure.command }
        try process.run()
        guard GuardianProcess.wait(process, seconds: min(4, remaining)) == 0 else { throw Failure.command }
        try writer.seek(toOffset: 0)
        let result = try writer.read(upToCount: 65537) ?? Data()
        guard result.count <= 65536,
              let text = String(data: result, encoding: .utf8), !text.contains("\0") else { throw Failure.readback }
        if diagnostics {
            guard lseek(descriptor, 0, SEEK_SET) == 0 else { throw Failure.io }
            let diagnostic = try FileHandle(fileDescriptor: descriptor, closeOnDealloc: false).read(upToCount: 65537) ?? Data()
            guard diagnostic.count <= 65536, let extra = String(data: diagnostic, encoding: .utf8),
                  !extra.contains("\0"), result.count + diagnostic.count <= 65536 else { throw Failure.readback }
            return (text + "\n" + extra).trimmingCharacters(in: .newlines)
        }
        return text.trimmingCharacters(in: .newlines)
    }

    private func install(_ rules: String) throws -> String {
        guard !rules.isEmpty, rules.utf8.count <= 16384, !rules.contains("\0") else { throw Failure.corrupt }
        let data = Data(rules.utf8)
        let canonical = try command(["-n", "-v", "-a", anchor, "-f", "-"], input: data)
        guard !canonical.isEmpty, canonical.utf8.count <= 32768 else { throw Failure.readback }
        _ = try command(["-a", anchor, "-f", "-"], input: data)
        guard try command(["-a", anchor, "-sr"]) == canonical else { throw Failure.readback }
        return canonical
    }

    private func emergencySeal(_ value: inout State) throws {
        value.lastRules = try install(emergency)
        let info = try command(["-s", "info"])
        if !info.split(whereSeparator: \.isNewline).contains(where: { $0.hasPrefix("Status: Enabled") }) {
            let output = try command(["-E"], diagnostics: true)
            let tokens = output.split(whereSeparator: \.isNewline).compactMap { line -> String? in
                let fields = line.split(separator: ":", omittingEmptySubsequences: false)
                guard fields.count == 2, fields[0].trimmingCharacters(in: .whitespaces) == "Token" else { return nil }
                let token = fields[1].trimmingCharacters(in: .whitespaces)
                return token.range(of: #"^[0-9]{1,20}\z"#, options: .regularExpression) != nil ? token : nil
            }
            guard tokens.count == 1 else { throw Failure.readback }
            let previous = value.pfToken
            value.pfToken = tokens[0]
            try save(value)
            if let previous, previous != value.pfToken { _ = try? command(["-X", previous]) }
            guard try command(["-s", "info"]).split(whereSeparator: \.isNewline)
                .contains(where: { $0.hasPrefix("Status: Enabled") }) else { throw Failure.readback }
        }
        _ = try command(["-F", "states"])
        try save(value)
    }

    func inhibit(forSleep: Bool = false) throws {
        let revocation = try publishRevocation(forSleep: forSleep)
        try locked {
            var value: State
            do { value = try state() }
            catch Failure.corrupt {
                guard let boot = GuardianStore.bootID() else { throw Failure.io }
                value = State(boot: boot)
            }
            // Durable intent is read atomically without taking the control
            // lock. Controls write disarming intent before acquiring this fence.
            let intentBytes = try bytes(directory + "/intent.json", maximum: 16384)
            let intent = intentBytes.flatMap { try? JSONDecoder().decode(GuardianIntent.self, from: $0) }
            let required = intentBytes != nil && (intent?.valid != true || intent?.armed == true || intent?.maintenance == true)
            var owned = value.session != nil || value.lastRules != nil || required
            if !owned, intentBytes == nil, let legacyRuntime {
                var metadata = stat()
                if lstat(legacyRuntime + "/active", &metadata) == 0, metadata.st_uid == owner,
                   metadata.st_mode & S_IFMT == S_IFDIR, metadata.st_mode & 0o777 == 0o700,
                   let session = try bytes(legacyRuntime + "/active/session", maximum: 64),
                   let text = String(data: session, encoding: .utf8),
                   UUID(uuidString: text.trimmingCharacters(in: .newlines)) != nil { owned = true }
            }
            value.powerBlocked = true
            value.revocation = revocation.id
            if revocation.sleepPending { value.sleepPending = true }
            value.session = nil
            value.clearedSession = nil
            value.openAllowed = false
            try save(value)
            if owned { try emergencySeal(&value) }
        }
    }

    func monitoringReady(waking: Bool = false) throws {
        try locked {
            try signaled {
                var value = try state()
                value.monitoring = true
                // A newer revocation published before writer-lock acquisition
                // belongs to a different power transition and cannot be cleared.
                if let pending = try revocation(), pending.id != value.revocation {
                    try save(value)
                    return
                }
                if waking { value.sleepPending = false }
                if value.sleepPending { try save(value); return }
                if value.powerBlocked {
                    value.powerBlocked = false
                    value.session = nil
                    value.openAllowed = false
                }
                if try revocation() != nil {
                    guard unlink(directory + "/filter-revocation") == 0 else { throw Failure.io }
                }
                try save(value)
            }
        }
    }

    func begin(_ session: String, openAllowed: Bool) throws {
        guard UUID(uuidString: session) != nil else { throw Failure.corrupt }
        try locked {
            var value = try state()
            guard value.monitoring, !value.powerBlocked, try revocation() == nil else { throw Failure.revoked }
            value.session = session
            value.clearedSession = nil
            value.openAllowed = openAllowed
            try save(value)
        }
    }

    func revokeOpen(forceSeal: Bool = false) throws {
        try locked {
            var value = try state()
            value.openAllowed = false
            try save(value)
            // A failed load/readback can leave actual OPEN rules while cached
            // rules still describe a seal. Never use that cached phase as proof
            // of restriction. Launch also seals when prior metadata is absent.
            if forceSeal || value.session != nil || value.lastRules != nil {
                try emergencySeal(&value)
            }
        }
    }

    var isAwake: Bool {
        (try? locked {
            let value = try state()
            let blocked = try revocation() != nil
            return value.monitoring && !value.powerBlocked && !blocked
        }) ?? false
    }

    func permitsOpen(_ session: String) -> Bool {
        (try? locked {
            let value = try state()
            let blocked = try revocation() != nil
            return value.monitoring && !value.powerBlocked && value.openAllowed && value.session == session && !blocked
        }) ?? false
    }

    func matchesSession(_ session: String) -> Bool {
        (try? locked {
            let value = try state()
            let blocked = try revocation() != nil
            return value.monitoring && !value.powerBlocked && value.session == session && !blocked
        }) ?? false
    }

    /// A new worker may inherit a native seal written while its predecessor
    /// was revoked. Foreign or changed rules cannot become adoption evidence.
    func confirmOwnership(_ rules: String, session: String) throws {
        try locked {
            let value = try state()
            guard value.monitoring, !value.powerBlocked, value.session == session, try revocation() == nil else { throw Failure.revoked }
            guard !rules.isEmpty, value.lastRules == rules,
                  try command(["-a", anchor, "-sr"]) == rules else { throw Failure.readback }
        }
    }

    func load(_ rules: String, phase: Phase, session: String) throws -> String {
        try locked {
            var value = try state()
            guard value.monitoring, !value.powerBlocked, value.session == session, try revocation() == nil,
                  phase != .open || value.openAllowed else { throw Failure.revoked }
            guard (phase == .open) == rules.contains("label \"CG_TUNNEL\"") else { throw Failure.corrupt }
            guard phase == .open || !rules.contains("label \"CG_LOOP\"") else { throw Failure.corrupt }
            do {
                let result = try install(rules)
                value.lastRules = result
                try save(value)
                return result
            } catch {
                value.session = nil
                value.openAllowed = false
                try? save(value)
                try? emergencySeal(&value)
                throw error
            }
        }
    }

    private func confirmEmpty() throws {
        if let remaining = try? command(["-a", anchor, "-sr"]) {
            guard remaining.isEmpty else { throw Failure.readback }
        } else {
            let anchors = try command(["-a", "com.apple", "-s", "Anchors"])
            let leaf = anchor.split(separator: "/").last.map(String.init) ?? anchor
            guard !anchors.split(whereSeparator: \.isWhitespace).contains(where: {
                $0 == leaf || $0 == anchor || $0.hasPrefix(leaf + "/") || $0.hasPrefix(anchor + "/")
            }) else { throw Failure.readback }
        }
    }

    private func clear(_ value: inout State) throws {
        value.clearedSession = value.session ?? value.clearedSession
        value.session = nil
        value.openAllowed = false
        try save(value)
        // Loading an empty anchor succeeds even if PF discarded it earlier.
        _ = try command(["-a", anchor, "-f", "-"])
        try confirmEmpty()
        value.lastRules = nil
        try save(value)
        if let token = value.pfToken {
            _ = try? command(["-X", token])
            value.pfToken = nil
            try save(value)
        }
    }

    /// Root control has already persisted disarming intent before this call.
    func clear() throws {
        try locked {
            var value: State
            do { value = try state() }
            catch Failure.corrupt {
                guard let boot = GuardianStore.bootID() else { throw Failure.io }
                value = State(boot: boot)
                if let pending = try revocation() {
                    value.revocation = pending.id
                    value.sleepPending = pending.boot == boot && pending.sleepPending
                }
            }
            try clear(&value)
        }
    }

    /// A worker may restore only its own expired trial or an already disarmed
    /// intent. It cannot clear a later session, maintenance or live approval.
    func clearWorker(_ session: String) throws {
        guard UUID(uuidString: session) != nil else { throw Failure.corrupt }
        try locked {
            var value = try state()
            guard let data = try bytes(directory + "/intent.json", maximum: 16384),
                  let intent = try? JSONDecoder().decode(GuardianIntent.self, from: data), intent.valid,
                  (!intent.armed && !intent.maintenance) ||
                    (intent.mode == "trial" && intent.armed && intent.session == session &&
                     intent.trialDeadline <= Int64(Date().timeIntervalSince1970)) else { throw Failure.revoked }
            if value.session == nil && value.clearedSession == session {
                try confirmEmpty()
                return
            }
            guard value.session == session else { throw Failure.revoked }
            try clear(&value)
        }
    }

    #if GUARD_DIAGNOSTICS
    func fixturePublishRevocation(forSleep: Bool) throws { _ = try publishRevocation(forSleep: forSleep) }
    static func fixture(directory: String, pf: String,
                        anchor: String = "com.apple/00000.org.claudeguard.runtime") throws -> GuardianPacketFence {
        try GuardianPacketFence(directory: directory, owner: getuid(), pf: pf, anchor: anchor)
    }
    #endif
}
