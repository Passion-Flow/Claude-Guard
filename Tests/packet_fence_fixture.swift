import Darwin
import Foundation

let guardSigningTeam = ""

@main enum PacketFenceFixture {
    static func check(_ value: Bool) { precondition(value) }
    static func rejects(_ action: () throws -> Void) {
        do { try action(); preconditionFailure("A revoked filter writer was accepted") }
        catch GuardianPacketFence.Failure.revoked {}
        catch { preconditionFailure("Unexpected fence failure") }
    }

    static func until(_ check: () -> Bool) {
        let deadline = ProcessInfo.processInfo.systemUptime + 3
        while !check() {
            precondition(ProcessInfo.processInfo.systemUptime < deadline)
            Thread.sleep(forTimeInterval: 0.01)
        }
    }

    static func main() throws {
        if CommandLine.arguments.count == 4 && CommandLine.arguments[1] == "--writer" {
            let root = URL(fileURLWithPath: CommandLine.arguments[2])
            let gate = try GuardianPacketFence.fixture(directory: root.appendingPathComponent("state").path,
                                                       pf: root.appendingPathComponent("pfctl").path)
            _ = try gate.load("pass quick on utun6 inet all no state label \"CG_TUNNEL\"\nblock drop quick all label \"CG_BLOCK\"\n",
                              phase: .open, session: CommandLine.arguments[3])
            return
        }
        precondition(CommandLine.arguments.dropFirst(2).compactMap(UInt32.init) == GuardianPowerObserver.fixtureMessageValues)
        let root = URL(fileURLWithPath: CommandLine.arguments[1])
        let state = root.appendingPathComponent("state").path
        let gate = try GuardianPacketFence.fixture(directory: state, pf: root.appendingPathComponent("pfctl").path)
        let other = try GuardianPacketFence.fixture(directory: state, pf: root.appendingPathComponent("pfctl").path)
        let rules = "pass quick on lo0 all no state label \"CG_LOOP\"\npass quick on utun6 inet all no state label \"CG_TUNNEL\"\nblock drop quick all label \"CG_BLOCK\"\n"
        let session = UUID().uuidString
        rejects { try gate.begin(session, openAllowed: true) }
        try gate.monitoringReady()
        try gate.begin(session, openAllowed: true)
        precondition(gate.isAwake && gate.permitsOpen(session))
        _ = try gate.load(rules, phase: .open, session: session)
        try gate.monitoringReady() // Duplicate readiness must not revoke a live session.
        _ = try gate.load(rules, phase: .open, session: session)
        try gate.inhibit()
        precondition(!gate.isAwake && !gate.permitsOpen(session))
        let filtered = root.appendingPathComponent("rules")
        check(!(try String(contentsOf: filtered, encoding: .utf8)).contains("CG_TUNNEL"))
        let nativeSeal = try String(contentsOf: filtered, encoding: .utf8)
        check(!nativeSeal.contains("CG_LOOP"))
        rejects { _ = try other.load(rules, phase: .open, session: session) }
        rejects { try other.confirmOwnership(nativeSeal, session: session) }
        rejects { try gate.begin(UUID().uuidString, openAllowed: true) }
        try gate.monitoringReady()
        let fresh = UUID().uuidString
        try gate.begin(fresh, openAllowed: true)
        try gate.confirmOwnership(nativeSeal, session: fresh)
        rejects { try gate.confirmOwnership(nativeSeal, session: session) }
        try (nativeSeal + "\npass quick all").write(to: filtered, atomically: true, encoding: .utf8)
        do { try gate.confirmOwnership(nativeSeal, session: fresh); preconditionFailure("Foreign PF contents were adopted") }
        catch GuardianPacketFence.Failure.readback {}
        try nativeSeal.write(to: filtered, atomically: true, encoding: .utf8)
        rejects { _ = try gate.load(rules, phase: .open, session: session) }
        _ = try gate.load(rules, phase: .open, session: fresh)
        try gate.revokeOpen()
        check(!(try String(contentsOf: filtered, encoding: .utf8)).contains("CG_TUNNEL"))
        rejects { _ = try gate.load(rules, phase: .open, session: fresh) }
        do { _ = try gate.load(rules, phase: .locked, session: fresh); preconditionFailure("OPEN rules accepted with a closed phase") }
        catch GuardianPacketFence.Failure.corrupt {}
        let oldClosed = "pass quick on lo0 all no state label \"CG_LOOP\"\nblock drop quick all label \"CG_BLOCK\"\n"
        do { _ = try gate.load(oldClosed, phase: .locked, session: fresh); preconditionFailure("Legacy loopback permission accepted while locked") }
        catch GuardianPacketFence.Failure.corrupt {}
        try gate.begin(fresh, openAllowed: true)

        // The PF writer remains alive while holding the native filter fence.
        // Inhibition must drain it, then seal; no queued old writer may follow.
        let hold = root.appendingPathComponent("hold")
        try Data().write(to: hold)
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global().async {
            defer { group.leave() }
            do { _ = try gate.load(rules, phase: .open, session: fresh) }
            catch { preconditionFailure("The admitted writer failed before inhibition") }
        }
        until { FileManager.default.fileExists(atPath: root.appendingPathComponent("entered").path) }
        group.enter()
        DispatchQueue.global().async {
            defer { group.leave() }
            do { try other.inhibit() }
            catch { preconditionFailure("Inhibition failed") }
        }
        until { FileManager.default.fileExists(atPath: state + "/filter-revocation") }
        let queued = try GuardianPacketFence.fixture(directory: state, pf: root.appendingPathComponent("pfctl").path)
        group.enter()
        DispatchQueue.global().async {
            defer { group.leave() }
            rejects { _ = try queued.load(rules, phase: .open, session: fresh) }
        }
        Thread.sleep(forTimeInterval: 0.05)
        precondition(group.wait(timeout: .now()) == .timedOut)
        try FileManager.default.removeItem(at: hold)
        precondition(group.wait(timeout: .now() + 5) == .success)
        check(!(try String(contentsOf: filtered, encoding: .utf8)).contains("CG_TUNNEL"))
        rejects { _ = try gate.load(rules, phase: .open, session: fresh) }
        try gate.clear()
        check((try String(contentsOf: filtered, encoding: .utf8)).isEmpty)
        rejects { _ = try gate.load(rules, phase: .sealed, session: fresh) }
        let record = URL(fileURLWithPath: state).appendingPathComponent("filter.json")
        try Data("invalid gate state".utf8).write(to: record)
        precondition(!gate.isAwake && !gate.permitsOpen(fresh))
        try gate.clear() // Explicit restoration may reset corrupt private metadata.
        precondition(!gate.isAwake)
        try gate.monitoringReady()
        let beforePower = UUID().uuidString
        try gate.begin(beforePower, openAllowed: true)
        _ = try gate.load(rules, phase: .open, session: beforePower)
        var sleepEvents = 0, wakeEvents = 0, failures = 0, acknowledgments = 0
        let power = GuardianPowerObserver(fence: gate, onSleep: { sleepEvents += 1 },
            onWake: { wakeEvents += 1 }, onFailure: { _ in failures += 1 })
        power.fixtureReady()
        power.fixtureEvent(.canSleep) { acknowledgments += 1 }
        precondition(acknowledgments == 1 && gate.permitsOpen(beforePower))
        power.fixtureEvent(.willSleep) {
            acknowledgments += 1
            precondition(!power.isAwake && !gate.permitsOpen(beforePower))
            precondition((try? String(contentsOf: filtered, encoding: .utf8).contains("CG_TUNNEL")) == false)
        }
        precondition(acknowledgments == 2 && sleepEvents == 1 && failures == 0)
        // A daemon restart after WillSleep must not clear the pending barrier
        // just because its new IOKit registration succeeds.
        try other.monitoringReady()
        precondition(!other.isAwake)
        power.fixtureEvent(.willPowerOn) { preconditionFailure("Early wake was acknowledged") }
        precondition(!gate.isAwake && wakeEvents == 0)
        power.fixtureEvent(.poweredOn) { preconditionFailure("Completed wake was acknowledged") }
        precondition(power.isAwake && gate.isAwake && wakeEvents == 1)
        rejects { _ = try gate.load(rules, phase: .open, session: beforePower) }
        let afterPower = UUID().uuidString
        try gate.begin(afterPower, openAllowed: true)
        power.fixtureEvent(.poweredOn) { preconditionFailure("Duplicate wake was acknowledged") }
        precondition(wakeEvents == 1 && gate.permitsOpen(afterPower))
        power.fixtureEvent(.willSleep) { acknowledgments += 1 }
        power.fixtureEvent(.sleepCancelled) { preconditionFailure("Sleep cancellation was acknowledged") }
        precondition(wakeEvents == 2 && sleepEvents == 2 && acknowledgments == 3 && failures == 0)

        let orphanSession = UUID().uuidString
        try gate.begin(orphanSession, openAllowed: true)
        for name in ["entered", "writer-finished", "seal-entered"] {
            let file = root.appendingPathComponent(name)
            if FileManager.default.fileExists(atPath: file.path) { try FileManager.default.removeItem(at: file) }
        }
        try Data().write(to: hold)
        let writer = Process()
        writer.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        writer.arguments = ["--writer", root.path, orphanSession]
        writer.standardInput = FileHandle.nullDevice
        writer.standardOutput = FileHandle.nullDevice
        writer.standardError = FileHandle.nullDevice
        try writer.run()
        until { FileManager.default.fileExists(atPath: root.appendingPathComponent("entered").path) }
        precondition(kill(writer.processIdentifier, SIGKILL) == 0)
        writer.waitUntilExit()
        let barrier = DispatchGroup()
        barrier.enter()
        DispatchQueue.global().async {
            defer { barrier.leave() }
            do { try other.inhibit() }
            catch { preconditionFailure("Orphan writer drain failed") }
        }
        let sealEntered = root.appendingPathComponent("seal-entered").path
        let observationDeadline = ProcessInfo.processInfo.systemUptime + 1
        while ProcessInfo.processInfo.systemUptime < observationDeadline && !FileManager.default.fileExists(atPath: sealEntered) {
            Thread.sleep(forTimeInterval: 0.01)
        }
        let enteredBeforeWriter = FileManager.default.fileExists(atPath: sealEntered)
        let completedBeforeWriter = barrier.wait(timeout: .now()) == .success
        try FileManager.default.removeItem(at: hold)
        until { FileManager.default.fileExists(atPath: root.appendingPathComponent("writer-finished").path) }
        precondition(barrier.wait(timeout: .now() + 5) == .success)
        let reopened = try String(contentsOf: filtered, encoding: .utf8).contains("CG_TUNNEL")
        FileHandle.standardError.write(Data("PARENT_DEATH_FENCE_RESULT entered=\(enteredBeforeWriter) early=\(completedBeforeWriter) reopened=\(reopened)\n".utf8))
        precondition(!enteredBeforeWriter && !completedBeforeWriter && !reopened,
                     "A surviving PF child wrote OPEN after its parent died and inhibition completed")
        try gate.monitoringReady()
        let clearSession = UUID().uuidString
        try gate.begin(clearSession, openAllowed: true)
        rejects { try gate.clearWorker(clearSession) } // No durable restore intent.
        let intentURL = URL(fileURLWithPath: state).appendingPathComponent("intent.json")
        func persist(_ intent: GuardianIntent) throws {
            precondition(intent.valid)
            try JSONEncoder().encode(intent).write(to: intentURL)
            precondition(chmod(intentURL.path, 0o600) == 0)
        }
        try persist(GuardianIntent())
        try gate.clearWorker(clearSession)
        try gate.clearWorker(clearSession) // Safe idempotence after a completed clear.
        let nextSession = UUID().uuidString
        try gate.begin(nextSession, openAllowed: true)
        rejects { try gate.clearWorker(clearSession) }
        var intent = GuardianIntent()
        intent.armed = true
        intent.session = nextSession
        intent.route = GuardianRoute(interface: "utun6", peer: "192.0.2.42", port: "443", transport: "tcp",
                                     expected: "192.0.2.42", region: "US", adminSource: "")
        intent.bootstrapHost = intent.route!.peer
        intent.bootID = GuardianStore.bootID()!
        intent.trialDeadline = Int64(Date().timeIntervalSince1970) + 60
        try persist(intent)
        rejects { try gate.clearWorker(nextSession) }
        intent.trialDeadline = Int64(Date().timeIntervalSince1970) - 1
        try persist(intent)
        try gate.clearWorker(nextSession)
        precondition(!gate.matchesSession(nextSession))

        let disabledSession = UUID().uuidString
        try gate.begin(disabledSession, openAllowed: true)
        _ = try gate.load(rules, phase: .open, session: disabledSession)
        try "Disabled".write(to: root.appendingPathComponent("pf-status"), atomically: true, encoding: .utf8)
        try gate.inhibit()
        check((try String(contentsOf: root.appendingPathComponent("pf-status"), encoding: .utf8)) == "Enabled")
        check(!(try String(contentsOf: filtered, encoding: .utf8)).contains("CG_TUNNEL"))
        try gate.clear()
        precondition(FileManager.default.fileExists(atPath: root.appendingPathComponent("native-token-released").path))

        // Publication closes admission before the writer lock is available.
        // A restart in that interval must inherit pending sleep rather than
        // interpreting registration success as permission to reopen.
        try gate.fixturePublishRevocation(forSleep: true)
        try other.monitoringReady()
        precondition(!other.isAwake)
        try other.inhibit()
        try other.monitoringReady()
        precondition(!other.isAwake)
        try other.monitoringReady(waking: true)
        precondition(other.isAwake)

        // Three individually valid 3.3-second PF commands used to outlast the
        // old eight-second acquisition timeout and acknowledge sleep with OPEN.
        // The complete writer now has one budget; sleep drains it and seals.
        let slowSession = UUID().uuidString
        try gate.begin(slowSession, openAllowed: true)
        _ = try gate.load(rules, phase: .open, session: slowSession)
        let slowCommands = root.appendingPathComponent("slow-commands")
        try Data().write(to: slowCommands)
        let slowWriter = DispatchGroup()
        slowWriter.enter()
        DispatchQueue.global().async {
            defer { slowWriter.leave() }
            _ = try? gate.load(rules, phase: .open, session: slowSession)
        }
        until { FileManager.default.fileExists(atPath: root.appendingPathComponent("slow-entered").path) }
        let slowPower = GuardianPowerObserver(fence: other, onSleep: {}, onWake: {}, onFailure: { _ in })
        slowPower.fixtureReady()
        var acknowledged = false
        let sleepStarted = ProcessInfo.processInfo.systemUptime
        slowPower.fixtureEvent(.willSleep) {
            acknowledged = true
            precondition((try? String(contentsOf: filtered, encoding: .utf8).contains("CG_TUNNEL")) == false)
            precondition(ProcessInfo.processInfo.systemUptime - sleepStarted < 25)
        }
        precondition(acknowledged && !other.permitsOpen(slowSession))
        precondition(slowWriter.wait(timeout: .now() + 2) == .success)
        try FileManager.default.removeItem(at: slowCommands)
        slowPower.fixtureEvent(.poweredOn) {}
        precondition(other.isAwake && slowPower.isAwake)
        rejects { _ = try other.load(rules, phase: .open, session: slowSession) }
        let recoveredSession = UUID().uuidString
        try other.begin(recoveredSession, openAllowed: true)
        _ = try other.load(rules, phase: .open, session: recoveredSession)
        print("SLOW_WRITER_SLEEP_RESULT acknowledged=true openAtAcknowledgment=false freshRecovery=true")
        print("PASS: native filter fence, default denial, power revocation, duplicate readiness, fresh wake session, in-flight writer drain and late-writer rejection after restoration")
    }
}
