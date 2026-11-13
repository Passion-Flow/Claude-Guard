import Darwin
import Foundation
import Security

enum GuardianInstaller {
    private static let components = [
        GuardianIdentity.application: "/Applications/Claude Guard.app",
        GuardianIdentity.daemon: GuardianTrust.directory + "/GuardDaemon",
        GuardianIdentity.recoveryDaemon: GuardianTrust.directory + "/GuardOfflineRecovery",
    ]

    static func validatePayload(at root: String) -> Bool {
        let prefix = root == "/" ? "" : root
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: prefix + GuardianTrust.directory + "/install-trust-template.json")),
              data.count <= 16384, let trust = try? JSONDecoder().decode(GuardianTrust.self, from: data), trust.valid else { return false }
        return validate(trust, prefix: prefix)
    }

    private static func validate(_ trust: GuardianTrust, prefix: String) -> Bool {
        for (identifier, path) in components {
            guard let expression = trust.requirement(identifier) else { return false }
            var requirement: SecRequirement?
            var code: SecStaticCode?
            guard SecRequirementCreateWithString(expression as CFString, [], &requirement) == errSecSuccess,
                  SecStaticCodeCreateWithPath(URL(fileURLWithPath: prefix + path) as CFURL, [], &code) == errSecSuccess,
                  let code,
                  SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate), requirement) == errSecSuccess else { return false }
        }
        return true
    }

    static func initialize() -> Int32 {
        guard geteuid() == 0, var trust = GuardianTrust.loadTemplate(), validate(trust, prefix: "") else { return 78 }
        var console = stat()
        if stat("/dev/console", &console) == 0 { trust.ownerUID = console.st_uid }
        do {
            let data = try JSONEncoder().encode(trust)
            let path = GuardianTrust.directory + "/install-trust.json"
            try data.write(to: URL(fileURLWithPath: path), options: .atomic)
            guard chmod(path, 0o644) == 0, chown(path, 0, 0) == 0, GuardianTrust.load() != nil else { return 78 }
            let store = try GuardianStore()
            try store.locked {
                try store.migrateLegacy(owner: trust.ownerUID)
                var intent = try store.read()
                intent.advanceControlRevision()
                try store.write(intent)
            }
            // Remove the obsolete recovery launcher only when its identity matches.
            let legacy = URL(fileURLWithPath: "/Applications/Claude Guard Recovery.app")
            if Bundle(url: legacy)?.bundleIdentifier == "org.claudeguard.recovery" {
                try FileManager.default.removeItem(at: legacy)
            }
            return 0
        } catch { return 74 }
    }

    static func uninstall(core: GuardianCore) -> Int32 {
        guard geteuid() == 0, GuardianTrust.load() != nil else { return 78 }
        let restored = core.restoreLocal()
        guard restored == 0 else { return restored }
        for label in [GuardianIdentity.daemon, GuardianIdentity.recoveryDaemon] {
            _ = launchctl(["bootout", "system/" + label])
            guard launchctl(["print", "system/" + label]) != 0 else { return 74 }
        }
        do {
            if let trust = GuardianTrust.load(), trust.ownerUID >= 501 {
                _ = launchctl(["bootout", "gui/" + String(trust.ownerUID) + "/org.claudeguard.mac"])
            }
            let agent = "/Library/LaunchAgents/org.claudeguard.mac.plist"
            if FileManager.default.fileExists(atPath: agent) { try FileManager.default.removeItem(atPath: agent) }
            for name in ["org.claudeguard.daemon.plist", "org.claudeguard.offline-recovery.plist"] {
                let path = "/Library/LaunchDaemons/" + name
                if FileManager.default.fileExists(atPath: path) { try FileManager.default.removeItem(atPath: path) }
            }
            for identifier in [GuardianIdentity.application] {
                if let path = components[identifier] { try FileManager.default.removeItem(atPath: path) }
            }
            try FileManager.default.removeItem(atPath: GuardianTrust.directory)
            return 0
        } catch { return 74 }
    }

    static func launchctl(_ arguments: [String]) -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run(); process.waitUntilExit(); return process.terminationStatus }
        catch { return 74 }
    }
}
