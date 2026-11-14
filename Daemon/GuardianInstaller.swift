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
            try installRecoveryKit()
            // Remove the obsolete recovery launcher only when its identity matches.
            let legacy = URL(fileURLWithPath: "/Applications/Claude Guard Recovery.app")
            if Bundle(url: legacy)?.bundleIdentifier == "org.claudeguard.recovery" {
                try FileManager.default.removeItem(at: legacy)
            }
            return 0
        } catch { return 74 }
    }

    static func uninstall() -> Int32 {
        guard geteuid() == 0 else { return 77 }
        do {
            try GuardianUninstall().perform()
            return 0
        } catch { return 74 }
    }

    private static func installRecoveryKit() throws {
        let path = GuardianUninstall.recoveryDirectory
        for parent in ["/Users", "/Users/Shared"] {
            var metadata = stat()
            guard lstat(parent, &metadata) == 0, metadata.st_uid == 0,
                  metadata.st_mode & S_IFMT == S_IFDIR else { throw GuardianUninstall.Failure.unsafePath }
        }
        if mkdir(path, 0o755) != 0 && errno != EEXIST { throw GuardianUninstall.Failure.filesystem }
        var metadata = stat()
        guard lstat(path, &metadata) == 0, metadata.st_uid == 0,
              metadata.st_mode & S_IFMT == S_IFDIR, metadata.st_mode & 0o022 == 0 else { throw GuardianUninstall.Failure.unsafePath }
        let source = URL(fileURLWithPath: "/Applications/Claude Guard.app/Contents/Resources/Uninstall.pkg")
        let destination = URL(fileURLWithPath: path).appendingPathComponent("Uninstall.pkg")
        let data = try Data(contentsOf: source)
        try data.write(to: destination, options: .atomic)
        guard chmod(destination.path, 0o644) == 0, chown(destination.path, 0, 0) == 0 else { throw GuardianUninstall.Failure.permission }
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
