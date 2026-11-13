import Darwin
import Foundation

enum GuardianSchema {
    static let policy = "ipv4-tunnel-v8"
    static let stateDirectory = GuardianTrust.directory + "/state"
}

struct GuardianIntent: Codable {
    static let initialControlRevision = "00000000-0000-0000-0000-000000000000"
    var schemaVersion = 2
    var policy = GuardianSchema.policy
    var ownerUID: UInt32 = 0
    var armed = false
    var persistent = false
    var maintenance = false
    var approved = false
    var session: String?
    var mode = "trial"
    var route: GuardianRoute?
    var serviceID: String?
    var riskKey: String?
    var trialDeadline: Int64 = 0
    var bootID = ""
    var automaticEnabled: Bool? = true
    var profileFingerprint: String?
    var bootstrapHost: String?
    var controlRevision: String?

    var effectiveControlRevision: String { controlRevision ?? Self.initialControlRevision }
    mutating func advanceControlRevision() { controlRevision = UUID().uuidString.lowercased() }

    var valid: Bool {
        guard schemaVersion == 2, policy == GuardianSchema.policy,
              ["trial", "live"].contains(mode), trialDeadline >= 0,
              controlRevision == nil || UUID(uuidString: controlRevision!) != nil else { return false }
        if armed || approved || maintenance {
            guard let route, route.valid, riskKey == nil || GuardRiskPolicy.validKey(riskKey!),
                  bootstrapHost == route.peer,
                  let session, UUID(uuidString: session) != nil, UUID(uuidString: bootID) != nil else { return false }
        }
        if mode == "live" && (armed || approved) {
            guard approved, serviceID == nil || UUID(uuidString: serviceID!) != nil else { return false }
        }
        if mode == "trial" && armed && trialDeadline == 0 { return false }
        return true
    }

    mutating func disarm() {
        advanceControlRevision()
        armed = false
        persistent = false
        maintenance = false
        approved = false
        session = nil
        route = nil
        serviceID = nil
        riskKey = nil
        trialDeadline = 0
        mode = "trial"
        bootstrapHost = nil
    }
}

final class GuardianStore {
    enum Failure: Error { case permission, corrupt, io, busy }
    let directory: String
    private let requiredOwner: uid_t
    private let descriptor: Int32
    private let localLock = NSLock()

    convenience init() throws {
        guard geteuid() == 0, GuardianTrust.load() != nil else { throw Failure.permission }
        try self.init(directory: GuardianSchema.stateDirectory, owner: 0)
    }

    private init(directory: String, owner: uid_t) throws {
        self.directory = directory
        requiredOwner = owner
        if mkdir(directory, 0o700) != 0 && errno != EEXIST { throw Failure.io }
        var metadata = stat()
        guard lstat(directory, &metadata) == 0, metadata.st_uid == owner,
              metadata.st_mode & S_IFMT == S_IFDIR, metadata.st_mode & 0o777 == 0o700 else { throw Failure.permission }
        let control = open(directory + "/control.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard control >= 0 else { throw Failure.io }
        guard fstat(control, &metadata) == 0, metadata.st_uid == owner,
              metadata.st_mode & S_IFMT == S_IFREG, metadata.st_mode & 0o777 == 0o600 else {
            close(control)
            throw Failure.permission
        }
        descriptor = control
    }

    deinit { close(descriptor) }

    func locked<Value>(_ body: () throws -> Value) throws -> Value {
        let deadline = ProcessInfo.processInfo.systemUptime + 8
        while !localLock.try() {
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw Failure.busy }
            Thread.sleep(forTimeInterval: 0.025)
        }
        defer { localLock.unlock() }
        while flock(descriptor, LOCK_EX | LOCK_NB) != 0 {
            guard errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR else { throw Failure.io }
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw Failure.busy }
            Thread.sleep(forTimeInterval: 0.025)
        }
        defer { flock(descriptor, LOCK_UN) }
        return try body()
    }

    private func readBytes() throws -> Data? {
        let path = directory + "/intent.json"
        let file = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if file < 0 {
            if errno == ENOENT { return nil }
            throw Failure.io
        }
        defer { close(file) }
        var metadata = stat()
        guard fstat(file, &metadata) == 0, metadata.st_uid == requiredOwner,
              metadata.st_mode & S_IFMT == S_IFREG, metadata.st_mode & 0o777 == 0o600,
              (1...16384).contains(metadata.st_size) else { throw Failure.permission }
        let handle = FileHandle(fileDescriptor: file, closeOnDealloc: false)
        guard let bytes = try handle.read(upToCount: 16385), bytes.count <= 16384 else { throw Failure.corrupt }
        return bytes
    }

    func read() throws -> GuardianIntent {
        guard let bytes = try readBytes() else { return GuardianIntent() }
        guard let value = try? JSONDecoder().decode(GuardianIntent.self, from: bytes), value.valid else { throw Failure.corrupt }
        return value
    }

    func migrateLegacy(owner: uid_t) throws {
        struct Legacy: Decodable {
            let schemaVersion: Int
            let policy: String
            let ownerUID: UInt32
            let armed: Bool
            let approved: Bool
            let maintenance: Bool
            let route: GuardianRoute?
            let automaticEnabled: Bool?
        }
        guard let bytes = try readBytes() else { return }
        if let current = try? JSONDecoder().decode(GuardianIntent.self, from: bytes), current.valid { return }
        let legacy = try JSONDecoder().decode(Legacy.self, from: bytes)
        guard legacy.schemaVersion == 1, ["ipv4-tunnel-v6", "ipv4-tunnel-v7"].contains(legacy.policy) else { throw Failure.corrupt }
        var next = GuardianIntent()
        next.advanceControlRevision()
        next.ownerUID = legacy.ownerUID == 0 ? owner : legacy.ownerUID
        next.automaticEnabled = legacy.automaticEnabled ?? true
        if legacy.armed || legacy.approved || legacy.maintenance {
            guard let route = legacy.route, route.valid, let boot = Self.bootID() else { throw Failure.corrupt }
            next.route = route
            next.bootstrapHost = route.peer // Sealed bootstrap metadata, never approval.
            next.maintenance = true
            next.persistent = true
            next.mode = "live"
            next.session = UUID().uuidString.lowercased()
            next.bootID = boot
            next.automaticEnabled = false
        }
        try write(next)
    }

    func write(_ value: GuardianIntent) throws {
        guard value.valid else { throw Failure.corrupt }
        let data = try JSONEncoder().encode(value)
        guard data.count <= 16384 else { throw Failure.corrupt }
        let temporary = directory + "/intent." + UUID().uuidString + ".tmp"
        let file = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw Failure.io }
        defer {
            close(file)
            unlink(temporary)
        }
        try data.withUnsafeBytes { bytes in
            var written = 0
            while written < bytes.count {
                let result = Darwin.write(file, bytes.baseAddress!.advanced(by: written), bytes.count - written)
                if result < 0 && errno == EINTR { continue }
                guard result > 0 else { throw Failure.io }
                written += result
            }
        }
        guard fsync(file) == 0, rename(temporary, directory + "/intent.json") == 0 else { throw Failure.io }
        let folder = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard folder >= 0 else { throw Failure.io }
        defer { close(folder) }
        guard fsync(folder) == 0 else { throw Failure.io }
    }

    static func bootID() -> String? {
        var length = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &length, nil, 0) == 0, (1...128).contains(length) else { return nil }
        var bytes = [CChar](repeating: 0, count: length)
        guard sysctlbyname("kern.bootsessionuuid", &bytes, &length, nil, 0) == 0 else { return nil }
        let value = String(cString: bytes)
        return UUID(uuidString: value)?.uuidString
    }

    #if GUARD_DIAGNOSTICS
    static func selfTest(at base: URL) throws -> Bool {
        let path = base.appendingPathComponent("guardian-store").path
        let store = try GuardianStore(directory: path, owner: getuid())
        return try store.locked {
            var value = try store.read()
            value.ownerUID = 501
            try store.write(value)
            guard try store.read().ownerUID == 501 else { return false }
            let secret = Data("broken state".utf8)
            try secret.write(to: URL(fileURLWithPath: path + "/intent.json"))
            do { _ = try store.read(); return false }
            catch Failure.corrupt { return true }
        }
    }
    #endif
}
