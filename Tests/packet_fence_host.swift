import Darwin
import Foundation

// Engineering-only executable. Never linked or copied into the product.
// Its fixed isolated anchor cannot modify the production guardian anchor.
let guardSigningTeam = ""

@main enum HostPacketFence {
    private static let directory = GuardianSchema.stateDirectory
    private static let anchor = "com.apple/00000.org.claudeguard.acceptance"
    private static let root = "/Library/PrivilegedHelperTools/org.claudeguard.acceptance"
    private static let eventLock = NSLock()

    private static func record(_ event: String) {
        eventLock.lock()
        defer { eventLock.unlock() }
        let url = URL(fileURLWithPath: root + "/power-events.json")
        var rows = (try? Data(contentsOf: url)).flatMap {
            try? JSONSerialization.jsonObject(with: $0) as? [[String: Any]]
        } ?? []
        rows.append(["event": event, "at": Date().timeIntervalSince1970])
        do {
            try JSONSerialization.data(withJSONObject: Array(rows.suffix(32)), options: .sortedKeys)
                .write(to: url, options: .atomic)
            guard chmod(url.path, 0o600) == 0 else { exit(78) }
        } catch { exit(74) }
    }

    private static func supervise() throws -> Never {
        let store = try GuardianStore()
        let fence = try GuardianPacketFence.fixture(directory: directory, pf: "/sbin/pfctl", anchor: anchor)
        var observer: GuardianPowerObserver?
        let core = GuardianCore(store: store, fence: fence, powerReady: { observer?.isAwake == true })
        observer = GuardianPowerObserver(fence: fence,
            onSleep: { record("sealed-before-sleep-acknowledgment"); core.powerWillSleep() },
            onWake: { record("completed-wake"); core.powerDidWake() },
            onFailure: { _ in record("power-failure"); core.powerFailed() })
        guard observer?.start() == true, observer?.isAwake == true else { throw GuardianPacketFence.Failure.revoked }
        record("registered-and-awake")
        core.startSupervision()
        let data = try Data(contentsOf: URL(fileURLWithPath: root + "/route.private.json"))
        guard data.count <= 16384,
              let config = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let interface = config["interface"] as? String, let peer = config["peer"] as? String,
              let port = config["port"] as? String, let transport = config["transport"] as? String,
              let expected = config["expected"] as? String, let region = config["region"] as? String else { exit(65) }
        let route = GuardianRoute(interface: interface, peer: peer, port: port,
                                  transport: transport, expected: expected, region: region, adminSource: "")
        guard route.valid else { exit(65) }
        let revision = try store.locked { try store.read().effectiveControlRevision }
        let request = GuardianRequest(.activate, session: UUID().uuidString.lowercased(), route: route,
            profileEvidence: TransportEvidence(endpointKey: route.endpointKey, kind: .vmessAEAD),
            profileFingerprint: String(repeating: "a", count: 64), profileServer: peer,
            controlRevision: revision, userInitiated: true)
        core.submit(request, uid: 0, authorization: Data(), recoveryOnly: false) {
            if $0.code != 0 { record("activation-failed"); exit($0.code) }
            record("activation-accepted")
        }
        withExtendedLifetime((core, observer)) { dispatchMain() }
    }

    static func main() {
        guard geteuid() == 0 else { exit(77) }
        let args = Array(CommandLine.arguments.dropFirst())
        do {
            if args == ["--supervise"] { try supervise() }
            if args.count == 2, args[0] == "--initialize", UUID(uuidString: args[1]) != nil {
                guard mkdir(directory, 0o700) == 0 else { exit(78) }
                let path = directory + "/intent.json"
                try JSONEncoder().encode(GuardianIntent()).write(to: URL(fileURLWithPath: path), options: .atomic)
                guard chmod(path, 0o600) == 0 else { exit(78) }
                let fence = try GuardianPacketFence.fixture(directory: directory, pf: "/sbin/pfctl", anchor: anchor)
                // Synthetic readiness for the isolated worker test only. The
                // installed daemon's actual IOKit lifecycle is tested separately.
                try fence.monitoringReady()
                try fence.begin(args[1], openAllowed: true)
                return
            }
            let fence = try GuardianPacketFence.fixture(directory: directory, pf: "/sbin/pfctl", anchor: anchor)
            if args == ["--restore"] {
                let store = try GuardianStore()
                let core = GuardianCore(store: store, fence: fence)
                exit(core.restoreLocal())
            }
            guard args.count >= 2, UUID(uuidString: args[1]) != nil else { exit(64) }
            if args.count == 2, args[0] == "--filter-clear" {
                let store = try GuardianStore()
                try store.locked { try fence.clearWorker(args[1]) }
                return
            }
            if args.count == 2, args[0] == "--filter-adopt" {
                let data = FileHandle.standardInput.readData(ofLength: 32769)
                guard data.count <= 32768, let rules = String(data: data, encoding: .utf8) else { exit(65) }
                try fence.confirmOwnership(rules, session: args[1])
                return
            }
            guard args.count == 3, args[0] == "--filter-load",
                  let phase = GuardianPacketFence.Phase(rawValue: args[2]) else { exit(64) }
            let data = FileHandle.standardInput.readData(ofLength: 16385)
            guard data.count <= 16384, let rules = String(data: data, encoding: .utf8) else { exit(65) }
            print(try fence.load(rules, phase: phase, session: args[1]))
        } catch GuardianPacketFence.Failure.revoked { exit(79) }
        catch { exit(74) }
    }
}
