import Darwin
import Foundation

@main enum ObservationFixture {
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
            Thread.sleep(forTimeInterval: 0.025)
        }
        preconditionFailure("Observation fixture timed out")
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
        if !CommandLine.arguments.contains("--expect-vulnerable") {
            let pausePublication = base.appendingPathComponent("pause-test-publication")
            try Data().write(to: pausePublication)
            Thread.sleep(forTimeInterval: 0.2)
            let proofPath = base.appendingPathComponent("runtime/evidence")
            let proof = try String(contentsOf: proofPath, encoding: .utf8)
            var parts = proof.trimmingCharacters(in: .newlines).components(separatedBy: "|")
            parts[2] = "LOCKED"
            let restrictive = "block drop quick all label \"CG_BLOCK\"\n"
            _ = try fence.load(restrictive, phase: .locked, session: session)
            let temporary = base.appendingPathComponent("restrictive-evidence")
            try (parts.joined(separator: "|") + "\n").write(to: temporary, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: temporary.path)
            precondition(rename(temporary.path, proofPath.path) == 0)
            Thread.sleep(forTimeInterval: 1.5)
            let unchanged = try store.locked { try store.read().session == session }
            precondition(unchanged, "Publication transition restarted the worker")
            let statusPath = base.appendingPathComponent("runtime/status")
            let statusText = try String(contentsOf: statusPath, encoding: .utf8)
            var statusParts = statusText.trimmingCharacters(in: .newlines).components(separatedBy: "|")
            statusParts[1] = "LOCKED"
            try (statusParts.joined(separator: "|") + "\n").write(to: statusPath, atomically: true, encoding: .utf8)
            try proof.write(to: temporary, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: temporary.path)
            precondition(rename(temporary.path, proofPath.path) == 0)
            Thread.sleep(forTimeInterval: 1.5)
            let unchangedAgain = try store.locked { try store.read().session == session }
            precondition(unchangedAgain, "Fresh evidence preceding UI OPEN restarted the worker")
            try FileManager.default.removeItem(at: pausePublication)
            until { request(GuardianRequest(.state), core: core).status?.components(separatedBy: "|")[1] == "OPEN" }
            print("PASS: restrictive and fresh OPEN evidence preceding UI status do not restart a healthy worker")
        }
        let admitting = base.appendingPathComponent("prepare-test-admission")
        if CommandLine.arguments.contains("--admitting") {
            try Data().write(to: admitting)
            until {
                let record = (try? String(contentsOf: base.appendingPathComponent("runtime/evidence"), encoding: .utf8)) ?? ""
                return record.contains("|ADMITTING|")
            }
            let beforeCommit = try String(contentsOf: base.appendingPathComponent("native-rules"), encoding: .utf8)
            precondition(!beforeCommit.contains("CG_TUNNEL"), "Prepared evidence granted traffic without a rule commit")
            if !CommandLine.arguments.contains("--expect-vulnerable") {
                let publicationPause = base.appendingPathComponent("pause-test-publication")
                try Data().write(to: publicationPause)
                Thread.sleep(forTimeInterval: 0.2)
                let statusPath = base.appendingPathComponent("runtime/status")
                var fields = try String(contentsOf: statusPath, encoding: .utf8).trimmingCharacters(in: .newlines).components(separatedBy: "|")
                fields[1] = "OPEN"
                try (fields.joined(separator: "|") + "\n").write(to: statusPath, atomically: true, encoding: .utf8)
                let state = request(GuardianRequest(.state), core: core).status?.components(separatedBy: "|")[1]
                precondition(state != "OPEN", "Prepared evidence was presented as committed OPEN")
                try FileManager.default.removeItem(at: publicationPause)
            }
        }
        let rules = "pass quick on utun6 inet all no state label \"CG_TUNNEL\"\nblock drop quick all label \"CG_BLOCK\"\n"
        _ = try fence.load(rules, phase: .open, session: session)
        let pause = base.appendingPathComponent("pause-test-proof")
        try Data().write(to: pause)
        Thread.sleep(forTimeInterval: 0.2)
        let record = try String(contentsOf: base.appendingPathComponent("runtime/evidence"), encoding: .utf8)
        let observed = Double(record.components(separatedBy: "|")[4])!
        let started = ProcessInfo.processInfo.systemUptime
        let allowance = max(0, 13 - (Date().timeIntervalSince1970 - observed))
        if CommandLine.arguments.contains("--expect-vulnerable") {
            Thread.sleep(forTimeInterval: allowance)
            let raw = try String(contentsOf: base.appendingPathComponent("native-rules"), encoding: .utf8)
            precondition(fence.permitsOpen(session) && raw.contains("CG_TUNNEL"))
            print("COUNTEREXAMPLE: fresh heartbeat retained kernel permission after observation expiry; admitting=\(CommandLine.arguments.contains("--admitting"))")
        } else {
            // The fake PF is a Python subprocess, so its write/readback cost
            // is not the host kernel's latency. Measure the native revocation
            // decision separately, then require bounded simulated sealing.
            until(seconds: max(0, 12.75 - (Date().timeIntervalSince1970 - observed))) {
                let path = URL(fileURLWithPath: store.directory).appendingPathComponent("filter.json")
                guard let data = try? Data(contentsOf: path),
                      let value = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return false }
                return value["openAllowed"] as? Bool == false
            }
            let revokedAge = Date().timeIntervalSince1970 - observed
            until(seconds: max(0, 15 - (Date().timeIntervalSince1970 - observed))) {
                let raw = (try? String(contentsOf: base.appendingPathComponent("native-rules"), encoding: .utf8)) ?? ""
                return raw.contains("CG_BLOCK") && !raw.contains("CG_TUNNEL") && !fence.permitsOpen(session)
            }
            let age = Date().timeIntervalSince1970 - observed
            precondition(revokedAge >= 11.75 && revokedAge < 12.75 && age < 15)
            print("PASS: native observation revocation age \(revokedAge); simulated PF seal age \(age); continuously fresh heartbeat")
            precondition(ProcessInfo.processInfo.systemUptime - started < 15)
        }
        try FileManager.default.removeItem(at: pause)
        if FileManager.default.fileExists(atPath: admitting.path) { try FileManager.default.removeItem(at: admitting) }
        until { request(GuardianRequest(.state), core: core).status?.components(separatedBy: "|")[1] == "OPEN" }
        precondition(request(GuardianRequest(.restore), core: core).code == 0)
        print("PASS: subsequent fresh admission and explicit restoration remain available")
    }

    static func main() {
        setbuf(stdout, nil)
        DispatchQueue.global().async {
            do { try run(URL(fileURLWithPath: CommandLine.arguments[1])); exit(0) }
            catch { print(error); exit(1) }
        }
        dispatchMain()
    }
}
