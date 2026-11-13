import Darwin
import Foundation

private final class GuardianSession: NSObject, GuardianProtocol {
    let core: GuardianCore
    let recoveryOnly: Bool

    init(core: GuardianCore, recoveryOnly: Bool) {
        self.core = core
        self.recoveryOnly = recoveryOnly
    }

    func submit(_ request: Data, authorization: Data, withReply reply: @escaping (Data) -> Void) {
        guard request.count <= 16384, authorization.count <= 128,
              let value = try? JSONDecoder().decode(GuardianRequest.self, from: request),
              let uid = NSXPCConnection.current()?.effectiveUserIdentifier else {
            reply((try? JSONEncoder().encode(GuardianResponse(code: 65))) ?? Data())
            return
        }
        core.submit(value, uid: uid, authorization: authorization, recoveryOnly: recoveryOnly) {
            reply((try? JSONEncoder().encode($0)) ?? Data())
        }
    }
}

private final class GuardianListener: NSObject, NSXPCListenerDelegate {
    let core: GuardianCore
    let recoveryOnly: Bool
    let requirement: String

    init(core: GuardianCore, recoveryOnly: Bool, requirement: String) {
        self.core = core
        self.recoveryOnly = recoveryOnly
        self.requirement = requirement
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.setCodeSigningRequirement(requirement)
        connection.exportedInterface = NSXPCInterface(with: GuardianProtocol.self)
        connection.exportedObject = GuardianSession(core: core, recoveryOnly: recoveryOnly)
        connection.resume()
        return true
    }
}

@main
enum GuardianDaemon {
    static func main() {
        let args = CommandLine.arguments
        if args.count == 3, args[1] == "--validate-risk" {
            let data = FileHandle.standardInput.readData(ofLength: 16385)
            exit(GuardRiskPolicy.evaluate(data, region: args[2]).rawValue)
        }
        if args.count == 2, args[1] == "--validate-keyless-risk" {
            let data = FileHandle.standardInput.readData(ofLength: 16482)
            guard let newline = data.firstIndex(of: 10), newline <= 80,
                  let context = String(data: data[..<newline], encoding: .utf8) else { exit(2) }
            let fields = context.components(separatedBy: "|")
            guard fields.count == 3 else { exit(2) }
            exit(GuardRiskPolicy.evaluateKeyless(Data(data[data.index(after: newline)...]),
                 region: fields[0], expected: fields[1], observedRegion: fields[2]).rawValue)
        }
        if args.count == 3, args[1] == "--validate-payload" {
            exit(GuardianInstaller.validatePayload(at: args[2]) ? 0 : 1)
        }
        #if GUARD_DIAGNOSTICS
        if args.count == 3, args[1] == "--self-test" {
            do {
                guard GuardianTrust.selfTest(), GuardRiskPolicy.selfTest(), GuardRiskPolicy.keylessSelfTest(),
                      try GuardianStore.selfTest(at: URL(fileURLWithPath: args[2], isDirectory: true)) else { exit(1) }
                print("PASS: installation trust, strict risk policy and atomic private state")
                exit(0)
            } catch { exit(1) }
        }
        #endif
        #if GUARD_OFFLINE_RECOVERY
        let filterCommand = false
        #else
        let filterCommand = (args.count == 4 && args[1] == "--filter-load") ||
            (args.count == 3 && ["--filter-clear", "--filter-adopt"].contains(args[1]))
        #endif
        guard filterCommand || args.count == 1 || (args.count == 2 && ["--initialize", "--prepare-upgrade", "--restore-local", "--uninstall"].contains(args[1])) else { exit(64) }
        guard geteuid() == 0 else { exit(77) }
        if args.count == 2, args[1] == "--initialize" { exit(GuardianInstaller.initialize()) }
        #if GUARD_OFFLINE_RECOVERY
        let identity = GuardianIdentity.recoveryDaemon
        #else
        let identity = GuardianIdentity.daemon
        #endif
        guard GuardianIdentity.currentProcessMatches(identity), let store = try? GuardianStore(),
              let fence = try? GuardianPacketFence() else { exit(78) }
        #if !GUARD_OFFLINE_RECOVERY
        if filterCommand {
            guard UUID(uuidString: args[2]) != nil else { exit(65) }
            do {
                if args[1] == "--filter-clear" {
                    // Serialize the deadline/intent decision with commit and
                    // restore. The power fence never takes this control lock.
                    try store.locked { try fence.clearWorker(args[2]) }
                }
                else if args[1] == "--filter-adopt" {
                    let data = FileHandle.standardInput.readData(ofLength: 32769)
                    guard data.count <= 32768, let rules = String(data: data, encoding: .utf8) else { exit(65) }
                    try fence.confirmOwnership(rules, session: args[2])
                } else {
                    guard let phase = GuardianPacketFence.Phase(rawValue: args[3]) else { exit(65) }
                    let data = FileHandle.standardInput.readData(ofLength: 16385)
                    guard data.count <= 16384, let rules = String(data: data, encoding: .utf8) else { exit(65) }
                    print(try fence.load(rules, phase: phase, session: args[2]))
                }
                exit(0)
            } catch GuardianPacketFence.Failure.revoked { exit(79) }
            catch { exit(74) }
        }
        #endif
        #if GUARD_OFFLINE_RECOVERY
        let core = GuardianCore(store: store, fence: fence,
                                recovery: GuardianRecovery(restartAfterRestore: !args.contains("--uninstall")))
        #else
        var powerObserver: GuardianPowerObserver?
        let core = GuardianCore(store: store, fence: fence, powerReady: { powerObserver?.isAwake == true })
        #endif
        if args.count == 2, args[1] == "--restore-local" { exit(core.restoreLocal()) }
        if args.count == 2, args[1] == "--prepare-upgrade" { exit(core.prepareUpgrade()) }
        if args.count == 2, args[1] == "--uninstall" { exit(GuardianInstaller.uninstall(core: core)) }
        guard args.count == 1 else { exit(64) }
        #if GUARD_OFFLINE_RECOVERY
        let channels = [(GuardianIdentity.recoveryDaemon, true)]
        #else
        let channels = [(GuardianIdentity.daemon, false), (GuardianIdentity.recoveryChannel, true)]
        powerObserver = GuardianPowerObserver(fence: fence,
            onSleep: { [weak core] in core?.powerWillSleep() },
            onWake: { [weak core] in core?.powerDidWake() },
            onFailure: { [weak core] _ in core?.powerFailed() })
        _ = powerObserver?.start()
        core.startSupervision()
        #endif
        var listeners: [NSXPCListener] = []
        var delegates: [GuardianListener] = []
        for (name, recoveryOnly) in channels {
            let identifier = GuardianIdentity.application
            guard let requirement = GuardianIdentity.requirement(identifier) else { exit(78) }
            let listener = NSXPCListener(machServiceName: name)
            listener.setConnectionCodeSigningRequirement(requirement)
            let delegate = GuardianListener(core: core, recoveryOnly: recoveryOnly, requirement: requirement)
            listener.delegate = delegate
            listeners.append(listener)
            delegates.append(delegate)
            listener.resume()
        }
        withExtendedLifetime((listeners, delegates, core)) { dispatchMain() }
    }
}
