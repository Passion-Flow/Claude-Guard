import Darwin
import Foundation

enum GuardianProcess {
    static func wait(_ process: Process, seconds: TimeInterval) -> Int32 {
        let deadline = ProcessInfo.processInfo.systemUptime + seconds
        while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval: 0.025) }
        if process.isRunning {
            process.terminate()
            let grace = ProcessInfo.processInfo.systemUptime + 0.5
            while process.isRunning && ProcessInfo.processInfo.systemUptime < grace { Thread.sleep(forTimeInterval: 0.025) }
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            process.waitUntilExit()
            return 124
        }
        process.waitUntilExit()
        return process.terminationStatus
    }
}

struct GuardianRecovery {
    let restartAfterRestore: Bool

    // The independent helper stops only the fixed, installer-owned primary job.
    // This releases a lock held by a stopped or wedged primary before recovery
    // takes that same lock. Workers retain their restrictive rules meanwhile.
    func stopMain() -> Int32 {
        _ = command(["bootout", "system/" + GuardianIdentity.daemon], timeout: 8)
        return command(["print", "system/" + GuardianIdentity.daemon], timeout: 2) == 113 ? 0 : 74
    }

    func restartMain() {
        guard restartAfterRestore else { return }
        _ = command(["bootstrap", "system", "/Library/LaunchDaemons/org.claudeguard.daemon.plist"], timeout: 8)
    }

    private func command(_ arguments: [String], timeout: TimeInterval) -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run(); return GuardianProcess.wait(process, seconds: timeout) }
        catch { return 74 }
    }
}
