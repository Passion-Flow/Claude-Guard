import Darwin
import Foundation

/// Administrator-authorized removal. This path deliberately does not require
/// the installed app, trust file, helper or approval state to remain present.
final class GuardianUninstall {
    struct Result {
        var code: Int32
        var output: String = ""
        var error: String = ""
    }
    struct User {
        let uid: uid_t
        let home: String
    }
    enum Failure: Error {
        case permission, unsafePath, filesystem, command, jobStillLoaded
        case processStillRunning, filterUnverified, receiptUnverified
    }

    static let anchor = "com.apple/00000.org.claudeguard.runtime"
    static let helperDirectory = "/Library/PrivilegedHelperTools/org.claudeguard"
    static let recoveryDirectory = "/Users/Shared/Claude Guard Recovery"
    static let systemLabels = ["org.claudeguard.daemon", "org.claudeguard.offline-recovery", "org.claudeguard.guardian"]
    static let receipts = ["org.claudeguard.private", "org.claudeguard.private.OfflineRecovery", "org.claudeguard.private.Uninstall"]
    static let preferenceDomains = ["org.claudeguard.mac", "org.claudeguard.appearance", "org.claudeguard.recovery"]

    private let prefix: String
    private let users: [User]
    private let command: (String, [String], TimeInterval) -> Result
    private let stopProcesses: () throws -> Void
    private let requiredOwner: uid_t
    private(set) var removedPaths = 0

    init() throws {
        guard geteuid() == 0 else { throw Failure.permission }
        prefix = ""
        requiredOwner = 0
        command = Self.execute
        users = try Self.localUsers()
        stopProcesses = Self.stopOwnedProcesses
    }

    #if GUARD_DIAGNOSTICS
    init(testRoot: String, users: [User] = [], command: @escaping (String, [String], TimeInterval) -> Result,
         stopProcesses: @escaping () throws -> Void = {}) {
        prefix = testRoot
        requiredOwner = getuid()
        self.users = users
        self.command = command
        self.stopProcesses = stopProcesses
    }
    #endif

    func perform() throws {
        // Separate administrator invocations must not race deletion and PF
        // release. Remove the lock file only while its final owner holds it.
        var lock: Int32 = -1
        let lockPath = "/private/var/run/org.claudeguard.uninstall.lock"
        if prefix.isEmpty {
            lock = open(lockPath, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
            var info = stat(), pathInfo = stat()
            guard lock >= 0 else { throw Failure.permission }
            guard fstat(lock, &info) == 0, info.st_uid == 0, info.st_mode & S_IFMT == S_IFREG,
                  info.st_mode & 0o077 == 0, info.st_nlink == 1,
                  flock(lock, LOCK_EX | LOCK_NB) == 0,
                  lstat(lockPath, &pathInfo) == 0, pathInfo.st_ino == info.st_ino, pathInfo.st_dev == info.st_dev else {
                close(lock); throw Failure.permission
            }
        }
        defer { if lock >= 0 { unlink(lockPath); close(lock) } }
        try removeInstallation()
    }

    private func removeInstallation() throws {
        // Preserve owned reference identifiers before a cleaner or removal
        // deletes their records. Unknown references are never guessed.
        let tokens = ownedTokens()
        let registrations = Self.systemLabels.map { "/Library/LaunchDaemons/" + $0 + ".plist" }
            + ["/Library/LaunchAgents/org.claudeguard.mac.plist"]
        // Remove persistence first. An interrupted uninstall must not register
        // an armed guardian again at the next boot or login.
        for path in registrations { try remove(path) }
        for label in Self.systemLabels { try stopJob("system/" + label) }
        for user in users { try stopJob("gui/" + String(user.uid) + "/org.claudeguard.mac", allowMissingDomain: true) }
        try stopProcesses()

        // No global PF disable, global rule flush or unrelated state flush.
        if try !anchorIsEmpty() {
            guard command("/sbin/pfctl", ["-a", Self.anchor, "-F", "rules"], 4).code == 0 else {
                throw Failure.filterUnverified
            }
        }
        guard try anchorIsEmpty() else { throw Failure.filterUnverified }
        for token in tokens {
            if command("/sbin/pfctl", ["-X", token], 4).code != 0 {
                let references = command("/sbin/pfctl", ["-s", "References"], 4)
                let absent = references.code == 0 && !references.output.split(whereSeparator: { !$0.isNumber }).contains(Substring(token))
                let noReferences = (references.output + references.error).contains("No pf_enabled references")
                guard absent || noReferences else { throw Failure.filterUnverified }
            }
        }

        for user in users {
            for domain in Self.preferenceDomains {
                // Ask the user's preferences service to discard cached values
                // before removing files, so it cannot later recreate them.
                let result = command("/bin/launchctl", ["asuser", String(user.uid), "/usr/bin/sudo", "-n", "-u",
                    "#" + String(user.uid), "--", "/usr/bin/defaults", "delete", domain], 5)
                if result.code != 0 && result.code != 1 && result.code != 125 && result.code != 113 {
                    throw Failure.command
                }
                for relative in ["Preferences/" + domain + ".plist", "Caches/" + domain,
                                 "HTTPStorages/" + domain, "WebKit/" + domain,
                                 "Saved Application State/" + domain + ".savedState",
                                 "Application Support/" + domain] {
                    try remove(user.home + "/Library/" + relative)
                }
            }
            try remove(user.home + "/Library/Application Support/Claude Guard")
            try remove(user.home + "/Library/Logs/Claude Guard")
        }
        for path in ["/Applications/Claude Guard.app", "/Applications/Claude Guard Recovery.app",
                     Self.helperDirectory, "/private/var/run/org.claudeguard.runtime", Self.recoveryDirectory] {
            try remove(path)
        }
        for identifier in Self.receipts { try forgetReceipt(identifier) }
        guard try anchorIsEmpty() else { throw Failure.filterUnverified }
        for label in Self.systemLabels {
            guard command("/bin/launchctl", ["print", "system/" + label], 3).code == 113 else {
                throw Failure.jobStillLoaded
            }
        }
    }

    private func stopJob(_ name: String, allowMissingDomain: Bool = false) throws {
        let before = command("/bin/launchctl", ["print", name], 3)
        if before.code == 113 || (allowMissingDomain && before.code == 125 && before.error.contains("Could not find domain")) { return }
        guard before.code == 0 else { throw Failure.command }
        _ = command("/bin/launchctl", ["bootout", name], 8)
        let after = command("/bin/launchctl", ["print", name], 3)
        guard after.code == 113 || (allowMissingDomain && after.code == 125 && after.error.contains("Could not find domain")) else {
            throw Failure.jobStillLoaded
        }
    }

    private func anchorIsEmpty() throws -> Bool {
        for attempt in 0..<3 {
            let result = command("/sbin/pfctl", ["-a", Self.anchor, "-sr"], 4)
            if result.error.contains("Resource busy") {
                if attempt < 2 { Thread.sleep(forTimeInterval: 0.05); continue }
                throw Failure.filterUnverified
            }
            if result.code == 0 { return result.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
            let parent = command("/sbin/pfctl", ["-a", "com.apple", "-s", "Anchors"], 4)
            guard parent.code == 0, !parent.error.contains("Resource busy") else { throw Failure.filterUnverified }
            let names = parent.output.split(whereSeparator: \.isWhitespace).map(String.init)
            guard !names.contains(where: { $0 == Self.anchor || $0 == "00000.org.claudeguard.runtime" ||
                $0.hasPrefix(Self.anchor + "/") || $0.hasPrefix("00000.org.claudeguard.runtime/") }) else {
                throw Failure.filterUnverified
            }
            return true
        }
        throw Failure.filterUnverified
    }

    private func forgetReceipt(_ identifier: String) throws {
        let before = command("/usr/sbin/pkgutil", ["--pkg-info", identifier], 4)
        if before.code == 1 { return }
        guard before.code == 0, command("/usr/sbin/pkgutil", ["--forget", identifier], 5).code == 0,
              command("/usr/sbin/pkgutil", ["--pkg-info", identifier], 4).code == 1 else {
            throw Failure.receiptUnverified
        }
    }

    private func ownedTokens() -> Set<String> {
        var values = Set<String>()
        func include(_ value: String?) {
            guard let value, !value.isEmpty, value.count <= 20,
                  value.utf8.allSatisfy({ (48...57).contains($0) }), UInt64(value) != nil else { return }
            values.insert(value)
        }
        if let data = try? ownedFile(Self.helperDirectory + "/state/filter.json", maximum: 131072),
           let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            include(object["pfToken"] as? String)
        }
        if let data = try? ownedFile("/private/var/run/org.claudeguard.runtime/active/token", maximum: 64) {
            include(String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return values
    }

    private func ownedFile(_ path: String, maximum: Int) throws -> Data {
        guard let (parent, leaf) = try parentOf(path) else { throw Failure.filesystem }
        defer { close(parent) }
        let descriptor = openat(parent, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Failure.filesystem }
        defer { close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == requiredOwner, metadata.st_mode & 0o022 == 0,
              metadata.st_size >= 0, metadata.st_size <= maximum else { throw Failure.unsafePath }
        return try FileHandle(fileDescriptor: descriptor, closeOnDealloc: false).read(upToCount: maximum + 1) ?? Data()
    }

    /// Walk through already-open directory descriptors. A user-controlled
    /// symlink cannot redirect root cleanup into a different directory.
    private func parentOf(_ path: String) throws -> (Int32, String)? {
        let components = (prefix + path).split(separator: "/").map(String.init)
        guard path.hasPrefix("/"), components.count > 1,
              !components.contains("."), !components.contains(".."), let leaf = components.last else { throw Failure.unsafePath }
        var directory = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw Failure.filesystem }
        for component in components.dropLast() {
            let next = openat(directory, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            let failure = errno
            close(directory)
            if next < 0 {
                if failure == ENOENT { return nil }
                throw Failure.unsafePath
            }
            directory = next
        }
        return (directory, leaf)
    }

    private func remove(_ path: String) throws {
        guard let (directory, leaf) = try parentOf(path) else { return }
        defer { close(directory) }
        if try Self.removeEntry(parent: directory, name: leaf, depth: 0) { removedPaths += 1 }
    }

    @discardableResult private static func removeEntry(parent: Int32, name: String, depth: Int) throws -> Bool {
        guard depth < 64, name != ".", name != "..", !name.contains("/") else { throw Failure.unsafePath }
        var metadata = stat()
        if fstatat(parent, name, &metadata, AT_SYMLINK_NOFOLLOW) != 0 {
            if errno == ENOENT { return false }
            throw Failure.filesystem
        }
        if metadata.st_mode & S_IFMT == S_IFDIR {
            let descriptor = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard descriptor >= 0 else { throw Failure.unsafePath }
            defer { close(descriptor) }
            let duplicate = dup(descriptor)
            guard duplicate >= 0 else { throw Failure.filesystem }
            guard let stream = fdopendir(duplicate) else { close(duplicate); throw Failure.filesystem }
            defer { closedir(stream) }
            while true {
                errno = 0
                guard let entry = readdir(stream) else {
                    guard errno == 0 else { throw Failure.filesystem }
                    break
                }
                let child = withUnsafePointer(to: &entry.pointee.d_name) {
                    $0.withMemoryRebound(to: CChar.self, capacity: Int(NAME_MAX) + 1) { String(cString: $0) }
                }
                if child == "." || child == ".." { continue }
                try removeEntry(parent: descriptor, name: child, depth: depth + 1)
            }
            guard unlinkat(parent, name, AT_REMOVEDIR) == 0 || errno == ENOENT else { throw Failure.filesystem }
        } else {
            guard unlinkat(parent, name, 0) == 0 || errno == ENOENT else { throw Failure.filesystem }
        }
        return true
    }

    static func execute(_ executable: String, _ arguments: [String], _ seconds: TimeInterval) -> Result {
        func temporary() -> Int32 {
            var template = Array("/private/tmp/claude-guard-command.XXXXXX".utf8CString)
            let fd = mkstemp(&template)
            if fd >= 0 { _ = unlink(template); _ = fcntl(fd, F_SETFD, FD_CLOEXEC) }
            return fd
        }
        let out = temporary(), err = temporary()
        guard out >= 0, err >= 0 else { if out >= 0 { close(out) }; if err >= 0 { close(err) }; return Result(code: 74) }
        defer { close(out); close(err) }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle(fileDescriptor: out, closeOnDealloc: false)
        process.standardError = FileHandle(fileDescriptor: err, closeOnDealloc: false)
        do {
            try process.run()
            let deadline = ProcessInfo.processInfo.systemUptime + seconds
            while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval: 0.025) }
            if process.isRunning {
                process.terminate()
                Thread.sleep(forTimeInterval: 0.1)
                if process.isRunning { kill(process.processIdentifier, SIGKILL) }
                process.waitUntilExit()
                return Result(code: 124)
            }
            process.waitUntilExit()
            func read(_ fd: Int32) throws -> String {
                _ = lseek(fd, 0, SEEK_SET)
                let data = try FileHandle(fileDescriptor: fd, closeOnDealloc: false).read(upToCount: 524289) ?? Data()
                guard data.count <= 524288, let value = String(data: data, encoding: .utf8) else { throw Failure.command }
                return value
            }
            return Result(code: process.terminationStatus, output: try read(out), error: try read(err))
        } catch { return Result(code: 74) }
    }

    private static func localUsers() throws -> [User] {
        let result = execute("/usr/bin/dscl", [".", "-list", "/Users", "UniqueID"], 5)
        guard result.code == 0 else { throw Failure.command }
        var users: [User] = []
        var seen = Set<uid_t>()
        for row in result.output.split(whereSeparator: \.isNewline) {
            guard let last = row.split(whereSeparator: \.isWhitespace).last,
                  let uid = UInt32(last), uid >= 501, uid < UInt32.max,
                  seen.insert(uid).inserted, let record = getpwuid(uid), let raw = record.pointee.pw_dir else { continue }
            let home = String(cString: raw)
            guard home.hasPrefix("/Users/"), home.split(separator: "/").count == 2 else { continue }
            users.append(User(uid: uid, home: home))
        }
        return users
    }

    private static func stopOwnedProcesses() throws {
        let workers = execute("/usr/bin/pgrep", ["-u", "0", "-f", " claude-guard-worker worker-input [0-9a-fA-F-]{36}$"], 4)
        guard workers.code == 0 || workers.code == 1 else { throw Failure.command }
        let apps = execute("/usr/bin/pgrep", ["-x", "ClaudeGuard|GuardDaemon|GuardOfflineRecovery"], 4)
        guard apps.code == 0 || apps.code == 1 else { throw Failure.command }
        for (output, worker) in [(workers.output, true), (apps.output, false)] {
            for raw in output.split(whereSeparator: \.isWhitespace) {
                guard let pid = Int32(raw), pid > 1, pid != getpid() else { throw Failure.command }
                func matches() -> Bool {
                    let info = execute("/bin/ps", ["-ww", "-p", String(pid), "-o", "uid=", "-o", worker ? "command=" : "comm="], 3)
                    guard info.code == 0 else { return false }
                    let fields = info.output.trimmingCharacters(in: .whitespacesAndNewlines).split(maxSplits: 1, whereSeparator: \.isWhitespace)
                    guard fields.count == 2 else { return false }
                    let value = String(fields[1])
                    if worker {
                        guard fields[0] == "0", let session = value.split(whereSeparator: \.isWhitespace).last,
                              UUID(uuidString: String(session)) != nil else { return false }
                        return value.hasSuffix(" claude-guard-worker worker-input " + session)
                    }
                    return value == "/Applications/Claude Guard.app/Contents/MacOS/ClaudeGuard" ||
                        value == "/Applications/Claude Guard Recovery.app/Contents/MacOS/ClaudeGuard" ||
                        (fields[0] == "0" && [helperDirectory + "/GuardDaemon", helperDirectory + "/GuardOfflineRecovery"].contains(value))
                }
                guard matches() else { continue }
                _ = kill(pid, SIGTERM)
                let deadline = ProcessInfo.processInfo.systemUptime + 2
                while matches() && ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval: 0.05) }
                if matches() { _ = kill(pid, SIGKILL); Thread.sleep(forTimeInterval: 0.1) }
                guard !matches() else { throw Failure.processStillRunning }
            }
        }
    }
}
