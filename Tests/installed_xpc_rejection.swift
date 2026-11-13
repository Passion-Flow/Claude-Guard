import Foundation

// Sign this engineering-only client with the app's identifier but a different
// code hash. It must be rejected by the actual installed Mach-service listener.
let guardSigningTeam = ""

private final class Observation {
    let signal = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var replied = false
    private var rejected = false
    func reply() { lock.lock(); replied = true; lock.unlock(); signal.signal() }
    func reject() { lock.lock(); rejected = true; lock.unlock(); signal.signal() }
    func result() -> (Bool, Bool) {
        lock.lock(); defer { lock.unlock() }
        return (replied, rejected)
    }
}

@main enum InstalledXPCRejection {
    static func main() throws {
        for channel in [GuardianIdentity.daemon, GuardianIdentity.recoveryChannel, GuardianIdentity.recoveryDaemon] {
            let observed = Observation()
            let connection = NSXPCConnection(machServiceName: channel, options: .privileged)
            connection.remoteObjectInterface = NSXPCInterface(with: GuardianProtocol.self)
            connection.invalidationHandler = { observed.reject() }
            connection.interruptionHandler = { observed.reject() }
            connection.resume()
            let proxy = connection.remoteObjectProxyWithErrorHandler { _ in observed.reject() } as? GuardianProtocol
            let request = try JSONEncoder().encode(GuardianRequest(.hello))
            proxy?.submit(request, authorization: Data()) { _ in observed.reply() }
            let finished = observed.signal.wait(timeout: .now() + 5) == .success
            let (replied, rejected) = observed.result()
            connection.invalidationHandler = nil
            connection.interruptionHandler = nil
            connection.invalidate()
            precondition(finished && rejected && !replied, "An unpinned client was not explicitly rejected")
            print("PASS: installed listener rejects unpinned client on \(channel)")
        }
    }
}
