import Darwin
import Foundation

enum FixtureWall {
    private static let lock = NSLock()
    private static var offset: TimeInterval = 0
    static func now() -> Date {
        lock.lock(); defer { lock.unlock() }
        return Date().addingTimeInterval(offset)
    }
    static func set(_ value: TimeInterval) {
        lock.lock(); defer { lock.unlock() }
        offset = value
        let path = URL(fileURLWithPath: CommandLine.arguments[1]).appendingPathComponent("clock-offset")
        do { try String(value).write(to: path, atomically: true, encoding: .utf8) }
        catch { preconditionFailure("Fixture wall clock could not be published") }
    }
}

@main enum ClockFixture {
    static func request(_ value: GuardianRequest, core: GuardianCore) -> GuardianResponse {
        let box = GuardianReplyBox()
        core.submit(value, uid: getuid(), authorization: Data(), recoveryOnly: false) { box.finish($0) }
        precondition(box.semaphore.wait(timeout: .now() + 15) == .success)
        return box.result()
    }

    static func until(seconds: TimeInterval = 12, _ predicate: () -> Bool) {
        let deadline = ProcessInfo.processInfo.systemUptime + seconds
        while ProcessInfo.processInfo.systemUptime < deadline {
            if predicate() { return }
            Thread.sleep(forTimeInterval: 0.05)
        }
        preconditionFailure("Clock fixture timed out")
    }

    static func run(_ base: URL) throws {
        let store = try GuardianStore()
        let fence = try GuardianPacketFence.fixture(directory: store.directory, pf: base.appendingPathComponent("pfctl").path)
        try fence.monitoringReady()
        let core = GuardianCore(store: store, fence: fence, powerReady: { true })
        core.startSupervision()
        let state = request(GuardianRequest(.state), core: core)
        let route = GuardianRoute(interface: "utun6", peer: "192.0.2.42", port: "443", transport: "tcp",
                                  expected: "192.0.2.42", region: "US", adminSource: "")
        let activation = GuardianRequest(.activate, session: UUID().uuidString, route: route,
            profileEvidence: TransportEvidence(endpointKey: route.endpointKey, kind: .vmessAEAD),
            profileFingerprint: String(repeating: "a", count: 64), profileServer: route.peer,
            controlRevision: state.controlRevision, userInitiated: true)
        precondition(request(activation, core: core).code == 0)
        until { request(GuardianRequest(.state), core: core).status?.components(separatedBy: "|")[1] == "OPEN" }
        let session = try store.locked { try store.read().session! }
        let rules = "pass quick on utun6 inet all no state label \"CG_TUNNEL\"\nblock drop quick all label \"CG_BLOCK\"\n"
        _ = try fence.load(rules, phase: .open, session: session)
        Thread.sleep(forTimeInterval: 2.1)
        precondition(fence.permitsOpen(session))
        print("CONTROL fresh-running permission retained")

        // The private fake worker keeps running but pauses only its test
        // heartbeat. No process is suspended and no real clock is changed.
        let pause = base.appendingPathComponent("pause-test-heartbeat")
        try Data().write(to: pause)
        FixtureWall.set(-3600)
        Thread.sleep(forTimeInterval: 17.1)
        let retained = fence.permitsOpen(session)
        let rawOpen = try String(contentsOf: base.appendingPathComponent("native-rules"), encoding: .utf8).contains("CG_TUNNEL")
        print("CLOCK_REWIND_RESULT heartbeatPaused=true elapsedSeconds=17 oldPermission=\(retained) oldRulesOpen=\(rawOpen)")
        if CommandLine.arguments.contains("--expect-vulnerable") {
            precondition(retained && rawOpen)
        } else {
            precondition(!retained && !rawOpen)
            let rotated = try store.locked { try store.read().session != session }
            precondition(rotated)
        }
        FixtureWall.set(0)
        try FileManager.default.removeItem(at: pause)
        until { request(GuardianRequest(.state), core: core).status?.components(separatedBy: "|")[1] == "OPEN" }
        let fresh = try store.locked { try store.read().session! }
        _ = try fence.load(rules, phase: .open, session: fresh)
        precondition(fence.permitsOpen(fresh))

        if !CommandLine.arguments.contains("--expect-vulnerable") {
            // A mature worker has no startup grace left. Repeated small
            // synthetic rewinds keep the unchanged heartbeat wall-age near one
            // second, but cannot extend its monotonic observation lifetime.
            Thread.sleep(forTimeInterval: 16.1)
            try Data().write(to: pause)
            let frozen = try String(contentsOf: base.appendingPathComponent("runtime/status"), encoding: .utf8)
            let stamp = Double(frozen.components(separatedBy: "|")[2])!
            let matureDeadline = ProcessInfo.processInfo.systemUptime + 17.1
            while ProcessInfo.processInfo.systemUptime < matureDeadline {
                FixtureWall.set(stamp + 1 - Date().timeIntervalSince1970)
                Thread.sleep(forTimeInterval: 0.4)
            }
            let retained = fence.permitsOpen(fresh)
            let rawOpen = try String(contentsOf: base.appendingPathComponent("native-rules"), encoding: .utf8).contains("CG_TUNNEL")
            print("REPEATED_REWIND_RESULT mature=true heartbeatPaused=true oldPermission=\(retained) oldRulesOpen=\(rawOpen)")
            if CommandLine.arguments.contains("--expect-heartbeat-vulnerable") {
                precondition(retained && rawOpen)
            } else {
                precondition(!retained && !rawOpen)
            }
            FixtureWall.set(0)
            try FileManager.default.removeItem(at: pause)
            until { request(GuardianRequest(.state), core: core).status?.components(separatedBy: "|")[1] == "OPEN" }
            FixtureWall.set(-30)
            until { request(GuardianRequest(.state), core: core).status?.components(separatedBy: "|")[1] == "OPEN" }
            FixtureWall.set(30)
            until { request(GuardianRequest(.state), core: core).status?.components(separatedBy: "|")[1] == "OPEN" }
            FixtureWall.set(0)
            until { request(GuardianRequest(.state), core: core).status?.components(separatedBy: "|")[1] == "OPEN" }
            print("CONTROL publishing heartbeat survives forward/backward fixture clock changes")
        }
        precondition(request(GuardianRequest(.restore), core: core).code == 0)
        print("CONTROL fresh heartbeat and explicit restoration remain available")
    }

    static func main() {
        DispatchQueue.global().async {
            do { try run(URL(fileURLWithPath: CommandLine.arguments[1])); exit(0) }
            catch { print(error); exit(1) }
        }
        dispatchMain()
    }
}
