import Darwin
import Foundation

@main enum RestartFixture {
    static func request(_ value: GuardianRequest, core: GuardianCore) -> GuardianResponse {
        let box = GuardianReplyBox()
        core.submit(value, uid: getuid(), authorization: Data(), recoveryOnly: false) { box.finish($0) }
        precondition(box.semaphore.wait(timeout: .now() + 15) == .success)
        return box.result()
    }

    static func until(_ predicate: () -> Bool) {
        let deadline = ProcessInfo.processInfo.systemUptime + 12
        while ProcessInfo.processInfo.systemUptime < deadline {
            if predicate() { return }
            Thread.sleep(forTimeInterval: 0.05)
        }
        preconditionFailure("Restart fixture timed out")
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
        func open() -> Bool {
            request(GuardianRequest(.state), core: core).status?.components(separatedBy: "|")[1] == "OPEN"
        }
        until { open() }
        let old = try store.locked { try store.read().session! }
        let rules = "pass quick on utun6 inet all no state label \"CG_TUNNEL\"\nblock drop quick all label \"CG_BLOCK\"\n"
        let marker = base.appendingPathComponent("fail-test-launch")
        let pidText = try String(contentsOf: base.appendingPathComponent("runtime/active/pid"), encoding: .utf8)
        let pid = Int32(pidText.trimmingCharacters(in: .whitespacesAndNewlines))!
        let began = ProcessInfo.processInfo.systemUptime
        let staleRules = CommandLine.arguments.contains("--stale-native-rules")
        try store.locked {
            try Data().write(to: marker)
            if staleRules {
                _ = try fence.load("block drop quick all label \"CG_BLOCK\"\n", phase: .sealed, session: old)
                try Data().write(to: base.appendingPathComponent("fail-test-open-readback"))
                try Data().write(to: base.appendingPathComponent("fail-test-seal-parse"))
                do {
                    _ = try fence.load(rules, phase: .open, session: old)
                    preconditionFailure("Injected readback failure was ignored")
                } catch {}
                let actual = try String(contentsOf: base.appendingPathComponent("native-rules"), encoding: .utf8)
                precondition(actual.contains("CG_TUNNEL") && !fence.permitsOpen(old))
            } else {
                _ = try fence.load(rules, phase: .open, session: old)
                precondition(fence.permitsOpen(old))
            }
            precondition(kill(pid, SIGKILL) == 0)
        }

        // Only this copied Core's future executable path is unavailable.
        // No host resource limit, installed process or system binary changes.
        until { (try? store.locked { try store.read().session }) != old }
        let expectedVulnerable = CommandLine.arguments.contains("--expect-vulnerable")
        var sessions = Set<String>()
        while ProcessInfo.processInfo.systemUptime - began < 17.1 {
            if let observed = try store.locked({ try store.read().session }) { sessions.insert(observed) }
            let open = try String(contentsOf: base.appendingPathComponent("native-rules"), encoding: .utf8).contains("CG_TUNNEL")
            if !expectedVulnerable { precondition(!open, "A failed retry retained tunnel-pass rules") }
            Thread.sleep(forTimeInterval: 0.05)
        }
        let rawOpen = try String(contentsOf: base.appendingPathComponent("native-rules"), encoding: .utf8).contains("CG_TUNNEL")
        let rotated = try store.locked { try store.read().session != old }
        let current = try store.locked { try store.read().session! }
        let permitted = fence.permitsOpen(current)
        print("RESTART_FAILURE_RESULT staleMetadata=\(staleRules) replacementUnavailable=true elapsedSeconds=17 sessionRotated=\(rotated) oldRulesOpen=\(rawOpen) failedLaunchPermitted=\(permitted)")
        precondition(rotated && sessions.count >= 2)
        if expectedVulnerable { precondition(rawOpen) }
        else { precondition(!rawOpen && !permitted) }

        try FileManager.default.removeItem(at: marker)
        core.powerDidWake() // Reset only the fixture's backoff for the control.
        until { open() }
        let fresh = try store.locked { try store.read().session! }
        precondition(fresh != old)
        _ = try fence.load(rules, phase: .open, session: fresh)
        precondition(fence.permitsOpen(fresh))
        precondition(request(GuardianRequest(.restore), core: core).code == 0)
        precondition(!fence.permitsOpen(fresh))
        print("CONTROL replacement launch and explicit restoration remain available")
    }

    static func main() {
        DispatchQueue.global().async {
            do { try run(URL(fileURLWithPath: CommandLine.arguments[1])); exit(0) }
            catch { print(error); exit(1) }
        }
        dispatchMain()
    }
}
