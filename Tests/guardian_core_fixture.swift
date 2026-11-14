import Darwin
import Foundation

@main enum CoreFixture {
    static let began = ProcessInfo.processInfo.systemUptime
    static func progress(_ stage: String) {
        let elapsed = String(format: "%.3f", ProcessInfo.processInfo.systemUptime - began)
        FileHandle.standardError.write(Data("CORE_FIXTURE_PROGRESS stage=\(stage) seconds=\(elapsed)\n".utf8))
    }
    static func precondition(_ condition: @autoclosure () -> Bool, _ message: String = "",
                             line: UInt = #line) {
        guard condition() else {
            FileHandle.standardError.write(Data("CORE_FIXTURE_ASSERTION line=\(line) \(message)\n".utf8))
            preconditionFailure("Core fixture failed")
        }
    }
    static func check(_ value: Bool) { precondition(value) }
    static func request(_ value: GuardianRequest, core: GuardianCore, uid: uid_t = getuid(), recovery: Bool = false,
                        freshIntent: Bool = false) -> GuardianResponse {
        var value = value
        if freshIntent {
            let state = request(GuardianRequest(.state), core: core, uid: uid)
            precondition(state.code == 0 && state.controlRevision != nil)
            value.controlRevision = state.controlRevision
            value.userInitiated = true
        }
        let box = GuardianReplyBox()
        core.submit(value, uid: uid, authorization: Data(), recoveryOnly: recovery) { box.finish($0) }
        precondition(box.semaphore.wait(timeout: .now() + 12) == .success, "Control reply timed out")
        return box.result()
    }

    static func until(line: UInt = #line, _ predicate: () -> Bool) {
        let deadline = Date().addingTimeInterval(12)
        while Date() < deadline {
            if predicate() { return }
            Thread.sleep(forTimeInterval: 0.05)
        }
        FileHandle.standardError.write(Data("CORE_FIXTURE_TIMEOUT line=\(line)\n".utf8))
        if let store = try? GuardianStore(), let intent = try? store.locked({ try store.read() }) {
            FileHandle.standardError.write(Data("CORE_FIXTURE_STATE armed=\(intent.armed) maintenance=\(intent.maintenance) approved=\(intent.approved) session=\(intent.session ?? "-")\n".utf8))
            if let bytes = try? Data(contentsOf: URL(fileURLWithPath: store.directory + "/filter.json")),
               var state = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any] {
                state.removeValue(forKey: "lastRules")
                if let text = try? JSONSerialization.data(withJSONObject: state, options: .sortedKeys) {
                    FileHandle.standardError.write(Data("CORE_FIXTURE_FENCE ".utf8) + text + Data("\n".utf8))
                }
            }
        }
        let runtime = URL(fileURLWithPath: CommandLine.arguments.last!).appendingPathComponent("runtime/status")
        if let status = try? String(contentsOf: runtime, encoding: .utf8) {
            FileHandle.standardError.write(Data("CORE_FIXTURE_STATUS \(status)\n".utf8))
        }
        preconditionFailure("Fixture condition did not become true")
    }

    static func run(at base: URL) throws {
        progress("begin")
        let store = try GuardianStore()
        let fence = try GuardianPacketFence.fixture(directory: store.directory,
                                                    pf: base.appendingPathComponent("pfctl").path)
        try fence.monitoringReady()
        var power: GuardianPowerObserver!
        let core = GuardianCore(store: store, fence: fence, powerReady: { power.isAwake })
        power = GuardianPowerObserver(fence: fence, onSleep: { core.powerWillSleep() },
            onWake: { core.powerDidWake() }, onFailure: { _ in core.powerFailed() })
        power.fixtureReady()
        let recoveryStore = try GuardianStore()
        let recovery = GuardianCore(store: recoveryStore, fence: fence)
        core.startSupervision()
        let route = GuardianRoute(interface: "utun6", peer: "192.0.2.42", port: "443", transport: "tcp",
                                  expected: "192.0.2.42", region: "US", adminSource: "")
        let key = "FixtureRiskKey0123456789"
        let link = "vless://fixture@192.0.2.42:443?security=reality&type=raw"
        func trial() -> GuardianResponse {
            request(GuardianRequest(.trial, session: UUID().uuidString.lowercased(), route: route, riskKey: key, nodeLink: link), core: core, freshIntent: true)
        }
        func phase(_ name: String) -> Bool {
            request(GuardianRequest(.state), core: core).status?.components(separatedBy: "|")[1] == name
        }
        GuardianTrust.ownerOverride = 0
        let unowned = request(GuardianRequest(.state), core: core, uid: getuid() + 1)
        precondition(unowned.code == 0 && unowned.controlRevision != nil && !unowned.active &&
                     unowned.automaticEnabled && unowned.status == nil && unowned.journal == nil &&
                     unowned.profileFingerprint == nil && unowned.revalidationRoute == nil)
        precondition(request(GuardianRequest(.restore), core: core, uid: getuid() + 1).code == 77)
        GuardianTrust.ownerOverride = nil
        precondition(request(GuardianRequest(.state), core: core, uid: getuid() + 1).code == 77)
        precondition(request(GuardianRequest(.trial), core: core, recovery: true).code == 65)
        precondition(request(GuardianRequest(.trial, session: UUID().uuidString, route: route, riskKey: key, nodeLink: "bad"), core: core).code == 65)
        precondition(trial().code == 0)
        until { phase("OPEN") }
        precondition(request(GuardianRequest(.commit, session: UUID().uuidString), core: core).code == 82)
        let trialSession = try store.locked { try store.read().session }
        precondition(request(GuardianRequest(.commit, session: trialSession), core: core, freshIntent: true).code == 0)
        check(try store.locked { let value = try store.read(); return value.approved && value.persistent && value.serviceID != nil })
        precondition(request(GuardianRequest(.pause), core: core, freshIntent: true).code == 0)
        until { phase("LOCKED") }
        precondition(request(GuardianRequest(.state), core: core).paused)
        precondition(request(GuardianRequest(.resume, session: UUID().uuidString.lowercased()), core: core, freshIntent: true).code == 0)
        until { phase("OPEN") }

        // Restart cannot reuse the old authorization generation.
        let prior = try store.locked { try store.read().session }
        let pid = try String(contentsOf: base.appendingPathComponent("runtime/active/pid"), encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        precondition(kill(Int32(pid)!, SIGKILL) == 0)
        until { (try? store.locked { try store.read().session }) != prior && phase("OPEN") }

        // Upgrade keeps a durable sealed state until explicit resume.
        precondition(core.prepareUpgrade() == 0)
        until { phase("LOCKED") }
        check(try store.locked { try store.read().maintenance })
        precondition(request(GuardianRequest(.resume, session: UUID().uuidString.lowercased()), core: core, freshIntent: true).code == 0)
        until { phase("OPEN") }

        // Corrupt durable approval must revoke a still-running worker.
        progress("restart-and-upgrade-passed")
        try store.locked {
            try Data("invalid intent".utf8).write(to: URL(fileURLWithPath: store.directory + "/intent.json"))
        }
        until { (try? String(contentsOf: base.appendingPathComponent("runtime/rules"), encoding: .utf8)) == "LOCKED" }
        precondition(request(GuardianRequest(.state), core: core).code == 74)
        precondition(request(GuardianRequest(.restore), core: recovery, recovery: true).code == 0)
        Thread.sleep(forTimeInterval: 2.2)
        check(try store.locked { let value = try store.read(); return !value.armed && !value.approved && !value.maintenance })
        precondition(!FileManager.default.fileExists(atPath: base.appendingPathComponent("runtime/active").path))

        // A missing intent file is not permission to keep an orphaned OPEN worker.
        precondition(trial().code == 0)
        until { phase("OPEN") }
        try store.locked { try FileManager.default.removeItem(atPath: store.directory + "/intent.json") }
        until { (try? String(contentsOf: base.appendingPathComponent("runtime/rules"), encoding: .utf8)) == "LOCKED" }
        precondition(request(GuardianRequest(.restore), core: recovery, recovery: true).code == 0)
        Thread.sleep(forTimeInterval: 1.2)

        // A trial restart retains its original absolute deadline.
        precondition(trial().code == 0)
        until { phase("OPEN") }
        try store.locked {
            var value = try store.read()
            value.trialDeadline = Int64(Date().timeIntervalSince1970) - 1
            try store.write(value)
        }
        until { (try? store.locked { try store.read().armed }) == false }
        Thread.sleep(forTimeInterval: 1)
        precondition(!FileManager.default.fileExists(atPath: base.appendingPathComponent("runtime/active").path))

        // Reproduce a stopped primary holding the shared lock. A bounded normal
        // attempt must fail, while authorized independent recovery preempts it.
        progress("durable-state-and-trial-expiry-passed")
        precondition(trial().code == 0)
        until { phase("OPEN") }
        let holder = Process()
        holder.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        holder.arguments = ["--hold-lock", base.path]
        try holder.run()
        until { FileManager.default.fileExists(atPath: base.appendingPathComponent("lock-holder.pid").path) }
        let contender = try GuardianStore()
        let waitBegan = Date()
        do { try contender.locked {}; preconditionFailure("A stopped lock owner was ignored") }
        catch GuardianStore.Failure.busy {}
        precondition(Date().timeIntervalSince(waitBegan) < 10)
        let independent = GuardianCore(store: try GuardianStore(), fence: fence,
                                       recovery: GuardianRecovery(restartAfterRestore: false))
        precondition(request(GuardianRequest(.restore), core: independent, uid: getuid() + 1, recovery: true).code == 77)
        precondition(holder.isRunning)
        let recoveryBegan = Date()
        precondition(request(GuardianRequest(.restore), core: independent, recovery: true).code == 0)
        holder.waitUntilExit()
        precondition(Date().timeIntervalSince(recoveryBegan) < 8)
        Thread.sleep(forTimeInterval: 1.2)
        check(try store.locked { try store.read().armed == false })
        precondition(!FileManager.default.fileExists(atPath: base.appendingPathComponent("runtime/active").path))
        // Automatic admission has no API key or trial confirmation, but still
        // requires authenticated, typed profile evidence and an exact endpoint.
        progress("independent-recovery-passed")
        let evidence = TransportEvidence(endpointKey: route.endpointKey, kind: .vmessAEAD)
        let fingerprint = String(repeating: "a", count: 64)
        let automatic = GuardianRequest(.activate, session: UUID().uuidString, route: route,
                                       profileEvidence: evidence, profileFingerprint: fingerprint, profileServer: route.peer)
        // Native fence readiness and observer publication are separate steps.
        // A supervisor in that interval may deny launch, but must not undo the
        // observer's ready fence and strand the subsequent completed wake.
        power.fixtureAwaitingReadiness()
        precondition(request(automatic, core: core, freshIntent: true).code == 74)
        precondition(fence.isAwake && !phase("OPEN"))
        power.fixtureReady()
        core.powerDidWake()
        until { phase("OPEN") }
        precondition(request(GuardianRequest(.restore), core: recovery, recovery: true).code == 0)
        precondition(request(GuardianRequest(.activate, session: UUID().uuidString, route: route), core: core).code == 65)
        precondition(request(automatic, core: core, recovery: true).code == 65)
        precondition(request(automatic, core: core, freshIntent: true).code == 0)
        until { phase("OPEN") }
        until { request(GuardianRequest(.state), core: core).revalidationRoute != nil }
        let pinnedService = try store.locked { try store.read().serviceID }
        check(try store.locked { let value = try store.read(); return value.persistent && value.approved && value.riskKey == nil && value.mode == "live" })
        precondition(request(GuardianRequest(.invalidate), core: core, freshIntent: true).code == 0)
        until { phase("LOCKED") }
        let invalidated = request(GuardianRequest(.state), core: core)
        precondition(!invalidated.canResume && !invalidated.paused)
        precondition(invalidated.profileFingerprint == nil && invalidated.revalidationRoute == route)
        precondition(request(GuardianRequest(.resume, session: UUID().uuidString), core: core).code == 82)
        let revokedSession = try store.locked { try store.read().session }
        precondition(request(GuardianRequest(.invalidate), core: core, freshIntent: true).code == 0)
        check(try store.locked { try store.read().session == revokedSession })
        precondition(request(automatic, core: core, freshIntent: true).code == 0)
        until { phase("OPEN") }
        check(try store.locked { try store.read().serviceID == pinnedService })
        let observedPID = Int32(try String(contentsOf: base.appendingPathComponent("runtime/active/pid"), encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines))!
        precondition(kill(observedPID, SIGSTOP) == 0)
        let statusURL = base.appendingPathComponent("runtime/status")
        let originalStatus = try String(contentsOf: statusURL, encoding: .utf8)
        var fields = originalStatus.trimmingCharacters(in: .newlines).components(separatedBy: "|")
        fields[1] = "LOCKED"
        fields[2] = String(Date().timeIntervalSince1970)
        fields[5] = "198.51.100.24"
        fields[6] = "exit-mismatch"
        try fields.joined(separator: "|").write(to: statusURL, atomically: true, encoding: .utf8)
        precondition(request(GuardianRequest(.state), core: core).revalidationRoute?.expected == fields[5])
        fields[2] = String(Date().timeIntervalSince1970 - 30)
        try fields.joined(separator: "|").write(to: statusURL, atomically: true, encoding: .utf8)
        precondition(request(GuardianRequest(.state), core: core).revalidationRoute?.expected == route.expected)
        fields[2] = String(Date().timeIntervalSince1970)
        fields[0] = UUID().uuidString
        try fields.joined(separator: "|").write(to: statusURL, atomically: true, encoding: .utf8)
        precondition(request(GuardianRequest(.state), core: core).revalidationRoute?.expected == route.expected)
        try originalStatus.write(to: statusURL, atomically: true, encoding: .utf8)
        precondition(kill(observedPID, SIGCONT) == 0)
        precondition(core.prepareUpgrade() == 0)
        try store.locked {
            let encoded = try JSONEncoder().encode(store.read())
            for (schema, policy) in [(1, "ipv4-tunnel-v7"), (2, "ipv4-tunnel-v8")] {
                var old = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
                old["schemaVersion"] = schema
                old["policy"] = policy
                if schema == 1 { old.removeValue(forKey: "bootstrapHost") }
                try JSONSerialization.data(withJSONObject: old).write(to: URL(fileURLWithPath: store.directory + "/intent.json"))
                try store.migrateLegacy(owner: getuid())
                let migrated = try store.read()
                precondition(!migrated.armed && !migrated.approved && migrated.maintenance && migrated.automaticEnabled == false)
                precondition(migrated.serviceID == pinnedService)
            }
        }
        until { phase("LOCKED") }
        let migrated = request(GuardianRequest(.state), core: core)
        precondition(!migrated.canResume && !migrated.automaticEnabled)
        precondition(migrated.revalidationRoute == route && migrated.profileFingerprint == nil)
        precondition(request(GuardianRequest(.resume, session: UUID().uuidString), core: core).code == 82)
        precondition(request(automatic, core: core, freshIntent: true).code == 0)
        until { phase("OPEN") }
        let beforeRecovery = request(GuardianRequest(.state), core: core)
        progress("automatic-admission-and-migration-passed")
        let queuedBeforeRecoveryInvalidation = GuardianRequest(.invalidate,
            controlRevision: beforeRecovery.controlRevision)
        var queuedAutomatic = automatic
        queuedAutomatic.controlRevision = beforeRecovery.controlRevision
        queuedAutomatic.userInitiated = false
        precondition(request(GuardianRequest(.restore), core: recovery, recovery: true).code == 0)
        Thread.sleep(forTimeInterval: 1.2)
        precondition(!request(GuardianRequest(.state), core: core).automaticEnabled)
        precondition(!FileManager.default.fileExists(atPath: base.appendingPathComponent("runtime/active").path))
        let staleInactiveInvalidation = request(queuedBeforeRecoveryInvalidation, core: core)
        FileHandle.standardError.write(Data("RESTORE_INVALIDATE_RESULT code=\(staleInactiveInvalidation.code) active=\(staleInactiveInvalidation.active) automatic=\(staleInactiveInvalidation.automaticEnabled)\n".utf8))
        precondition(staleInactiveInvalidation.code == 79,
                     "A stale invalidation must not acknowledge a deferred setup continuation after recovery")
        let delayedActivation = request(queuedAutomatic, core: core)
        FileHandle.standardError.write(Data("RESTORE_REPLAY_RESULT active=\(delayedActivation.active) automatic=\(delayedActivation.automaticEnabled)\n".utf8))
        precondition(!delayedActivation.active && !delayedActivation.automaticEnabled,
                     "A delayed activation rearmed protection after independent recovery")
        var queuedExplicit = queuedAutomatic
        queuedExplicit.userInitiated = true
        precondition(request(queuedExplicit, core: core).code == 79)
        let recoveredState = request(GuardianRequest(.state), core: core)
        precondition(recoveredState.revalidationRoute == nil && recoveredState.profileFingerprint == nil)
        let queuedTrial = GuardianRequest(.trial, session: UUID().uuidString, route: route, riskKey: key, nodeLink: link,
            controlRevision: recoveredState.controlRevision, userInitiated: true)
        precondition(request(GuardianRequest(.restore), core: recovery, recovery: true).code == 0)
        let newCore = GuardianCore(store: try GuardianStore(), fence: fence, powerReady: { power.isAwake })
        precondition(request(queuedTrial, core: newCore).code == 79)
        precondition(request(queuedExplicit, core: newCore).code == 79)
        var newBackground = automatic
        newBackground.controlRevision = request(GuardianRequest(.state), core: newCore).controlRevision
        newBackground.userInitiated = false
        precondition(request(newBackground, core: newCore).code == 79)
        precondition(!request(GuardianRequest(.state), core: newCore).active)
        precondition(request(automatic, core: core, freshIntent: true).code == 0)
        until { phase("OPEN") }
        precondition(request(GuardianRequest(.pause), core: core, freshIntent: true).code == 0)
        until { phase("LOCKED") }
        let pausedState = request(GuardianRequest(.state), core: core)
        let queuedResume = GuardianRequest(.resume, session: UUID().uuidString,
            controlRevision: pausedState.controlRevision, userInitiated: true)
        precondition(request(GuardianRequest(.resume, session: UUID().uuidString), core: core, freshIntent: true).code == 0)
        until { phase("OPEN") }
        precondition(request(GuardianRequest(.pause), core: core, freshIntent: true).code == 0)
        until { phase("LOCKED") }
        precondition(request(queuedResume, core: core).code == 79)
        var pausedAutomatic = automatic
        pausedAutomatic.controlRevision = request(GuardianRequest(.state), core: core).controlRevision
        pausedAutomatic.userInitiated = false
        precondition(request(pausedAutomatic, core: core).code == 82)
        precondition(request(GuardianRequest(.state), core: core).paused)
        precondition(request(GuardianRequest(.resume, session: UUID().uuidString), core: core, freshIntent: true).code == 0)
        until { phase("OPEN") }
        let queuedInvalidation = GuardianRequest(.invalidate,
            controlRevision: request(GuardianRequest(.state), core: core).controlRevision)
        precondition(request(GuardianRequest(.pause), core: core, freshIntent: true).code == 0)
        until { phase("LOCKED") }
        precondition(request(GuardianRequest(.resume, session: UUID().uuidString), core: core, freshIntent: true).code == 0)
        until { phase("OPEN") }
        precondition(request(queuedInvalidation, core: core).code == 79)
        precondition(request(GuardianRequest(.invalidate), core: core, freshIntent: true).code == 0)
        until { phase("LOCKED") }
        var freshAutomatic = automatic
        freshAutomatic.session = UUID().uuidString
        freshAutomatic.controlRevision = request(GuardianRequest(.state), core: core).controlRevision
        freshAutomatic.userInitiated = false
        precondition(request(freshAutomatic, core: core).code == 0)
        until { phase("OPEN") }

        // A fallback seal from a transient filter/control failure is distinct
        // from pending sleep. A registered, awake observer permits fresh
        // supervision after metadata recovery, without manual restore.
        progress("stale-intent-and-replay-controls-passed")
        let fallbackSession = try store.locked { try store.read().session }
        try fence.inhibit()
        until { (try? store.locked { try store.read().session }) != fallbackSession && phase("OPEN") }

        // A durable pending-sleep signal remains sealed even if the separate
        // observer's awake publication has not changed yet. Ordinary retries
        // cannot stand in for a completed-wake event.
        let pendingSleepSession = try store.locked { try store.read().session }
        try fence.inhibit(forSleep: true)
        Thread.sleep(forTimeInterval: 6.2)
        precondition(!fence.isAwake && !fence.permitsOpen(pendingSleepSession!) && !phase("OPEN"))
        power.fixtureEvent(.willSleep) {}
        power.fixtureEvent(.poweredOn) {}
        until { (try? store.locked { try store.read().session }) != pendingSleepSession && phase("OPEN") }

        // Local restore repairs private fence metadata without requiring a
        // reboot or weakening the observer's separate pending-sleep barrier.
        try Data("invalid fence metadata".utf8).write(to: URL(fileURLWithPath: store.directory + "/filter.json"))
        precondition(request(GuardianRequest(.restore), core: core).code == 0)
        precondition(fence.isAwake && !request(GuardianRequest(.state), core: core).active)
        precondition(request(automatic, core: core, freshIntent: true).code == 0)
        until { phase("OPEN") }

        // A sleep shorter than the identity lease still revokes OPEN before
        // acknowledgment and starts an entirely fresh worker after full wake.
        let preSleepSession = try store.locked { try store.read().session }
        power.fixtureEvent(.willSleep) {
            precondition(!fence.permitsOpen(preSleepSession!))
            precondition(!phase("OPEN"))
        }
        power.fixtureEvent(.willPowerOn) { preconditionFailure("Early wake acknowledgment") }
        precondition(!phase("OPEN"))
        power.fixtureEvent(.poweredOn) { preconditionFailure("Completed wake acknowledgment") }
        until { (try? store.locked { try store.read().session }) != preSleepSession && phase("OPEN") }

        // Pause and upgrade intent survive sleep; wake cannot silently resume.
        precondition(request(GuardianRequest(.pause), core: core, freshIntent: true).code == 0)
        until { phase("LOCKED") }
        power.fixtureEvent(.willSleep) {}
        power.fixtureEvent(.poweredOn) {}
        until { phase("LOCKED") && request(GuardianRequest(.state), core: core).paused }
        precondition(request(GuardianRequest(.resume, session: UUID().uuidString), core: core, freshIntent: true).code == 0)
        until { phase("OPEN") }
        precondition(core.prepareUpgrade() == 0)
        power.fixtureEvent(.willSleep) {}
        power.fixtureEvent(.poweredOn) {}
        until { phase("LOCKED") && request(GuardianRequest(.state), core: core).paused }
        precondition(request(GuardianRequest(.resume, session: UUID().uuidString), core: core, freshIntent: true).code == 0)
        until { phase("OPEN") }

        // Independent restore during suspension wins over the queued wake.
        power.fixtureEvent(.willSleep) {}
        precondition(request(GuardianRequest(.restore), core: recovery, recovery: true).code == 0)
        power.fixtureEvent(.poweredOn) {}
        Thread.sleep(forTimeInterval: 1.2)
        let afterWakeRestore = request(GuardianRequest(.state), core: core)
        precondition(!afterWakeRestore.active && !afterWakeRestore.automaticEnabled)
        precondition(!FileManager.default.fileExists(atPath: base.appendingPathComponent("runtime/active").path))
        progress("sleep-wake-and-restoration-passed")
        print("PASS: root-authoritative admission, authorization denial, durable recovery, stale activation/invalidation/trial/resume rejection, fresh explicit enable, automatic revalidation, commit/pause/resume, fresh restart sessions, sealed upgrade, corrupt/missing-state revocation, bounded locks, preemptive independent recovery, trial expiry, automatic non-sleep seal recovery and pending/short-sleep/pause/upgrade/restore wake boundaries")
    }

    static func main() {
        if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--hold-lock" {
            do {
                let store = try GuardianStore()
                try store.locked {
                    try String(getpid()).write(toFile: CommandLine.arguments[2] + "/lock-holder.pid", atomically: true, encoding: .utf8)
                    raise(SIGSTOP)
                    while true { Thread.sleep(forTimeInterval: 1) }
                }
            } catch { exit(1) }
        }
        DispatchQueue.global().async {
            do { try run(at: URL(fileURLWithPath: CommandLine.arguments[1])); exit(0) }
            catch { print(error); exit(1) }
        }
        dispatchMain()
    }
}
