import Darwin
import Foundation

/// Runs only after Installer has obtained administrator authorization.
/// All executable code is carried inside this package, not the installation.
@main
enum UninstallMain {
    private static let receipt = "org.claudeguard.private.Uninstall"

    static func main() {
        guard geteuid() == 0 else { exit(77) }
        let args = CommandLine.arguments
        guard args.count == 2 else { exit(64) }
        if args[1] == "--finish-receipt" { finishReceipt(); return }
        if args[1] == "--remove-only" {
            do { try GuardianUninstall().perform(); exit(0) }
            catch { exit(74) }
        }
        guard args[1] == "--uninstall" else { exit(64) }
        var stage: URL?
        do {
            // Prepare the one-shot receipt cleanup before removing anything.
            // Installer writes this package's receipt only after postinstall
            // returns, so deleting it synchronously would leave a new receipt.
            let directory = try makeFinisher()
            stage = directory
            try GuardianUninstall().perform()
            let result = GuardianUninstall.execute("/bin/launchctl", ["bootstrap", "system", directory.appendingPathComponent("finish.plist").path], 8)
            guard result.code == 0 else { throw GuardianUninstall.Failure.command }
            stage = nil
            print("Claude Guard was removed. Its packet rules, startup jobs and local state are no longer active. Installer receipt cleanup finishes automatically after this installation closes.")
        } catch {
            if let stage { try? FileManager.default.removeItem(at: stage) }
            // Do not expose addresses, credentials or file contents in logs.
            fputs("Claude Guard removal did not finish. Run this standalone Uninstall.pkg again; the installed app and helpers are not required.\n", stderr)
            exit(74)
        }
    }

    private static func makeFinisher() throws -> URL {
        var template = Array("/private/var/tmp/org.claudeguard.uninstall.XXXXXX".utf8CString)
        guard mkdtemp(&template) != nil else { throw GuardianUninstall.Failure.filesystem }
        let directory = URL(fileURLWithPath: String(cString: template), isDirectory: true)
        do {
            guard chmod(directory.path, 0o700) == 0 else { throw GuardianUninstall.Failure.permission }
            let executable = directory.appendingPathComponent("GuardUninstall")
            guard let source = Bundle.main.executableURL else { throw GuardianUninstall.Failure.filesystem }
            try FileManager.default.copyItem(at: source, to: executable)
            guard chmod(executable.path, 0o700) == 0 else { throw GuardianUninstall.Failure.permission }
            let label = "org.claudeguard.uninstall-finish." + directory.lastPathComponent.components(separatedBy: ".").last!
            let job: [String: Any] = ["Label": label, "ProgramArguments": [executable.path, "--finish-receipt"],
                "RunAtLoad": true, "ProcessType": "Background"]
            let data = try PropertyListSerialization.data(fromPropertyList: job, format: .xml, options: 0)
            try data.write(to: directory.appendingPathComponent("finish.plist"), options: .atomic)
            return directory
        } catch { try? FileManager.default.removeItem(at: directory); throw error }
    }

    private static func finishReceipt() {
        guard let executable = Bundle.main.executableURL else { exit(78) }
        let directory = executable.deletingLastPathComponent()
        guard directory.deletingLastPathComponent().path == "/private/var/tmp",
              directory.lastPathComponent.range(of: #"^org\.claudeguard\.uninstall\.[A-Za-z0-9]{6}$"#, options: .regularExpression) != nil else { exit(78) }
        var metadata = stat()
        guard lstat(directory.path, &metadata) == 0, metadata.st_uid == 0,
              metadata.st_mode & S_IFMT == S_IFDIR, metadata.st_mode & 0o077 == 0 else { exit(78) }
        let label = "org.claudeguard.uninstall-finish." + directory.lastPathComponent.components(separatedBy: ".").last!
        let deadline = ProcessInfo.processInfo.systemUptime + 90
        // This job has no network privileges beyond those of an ordinary root
        // process and never writes PF, approval state, or another app's files.
        // It has no boot plist and no KeepAlive; it cannot become protection.
        while ProcessInfo.processInfo.systemUptime < deadline {
            let installed = GuardianUninstall.execute("/usr/sbin/pkgutil", ["--pkg-info", receipt], 4)
            if installed.code == 0 {
                let forgotten = GuardianUninstall.execute("/usr/sbin/pkgutil", ["--forget", receipt], 4)
                if forgotten.code == 0 && GuardianUninstall.execute("/usr/sbin/pkgutil", ["--pkg-info", receipt], 4).code == 1 { break }
            }
            Thread.sleep(forTimeInterval: 0.5)
        }
        try? FileManager.default.removeItem(at: directory)
        _ = GuardianUninstall.execute("/bin/launchctl", ["bootout", "system/" + label], 4)
    }
}
