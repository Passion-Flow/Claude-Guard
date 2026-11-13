import Darwin
import Foundation

// Only OS profile/network observations are substituted. Store migration, Core
// responses and AutomaticRoute are the production implementations.
struct GuardConfiguration {
    static func validInterface(_ value: String) -> Bool {
        value.range(of: #"^utun[0-9]+\z"#, options: .regularExpression) != nil
    }
}
struct LocalCheck {
    var vpnConnected = false
    var defaultInterface = "en0"
    static func read() -> Self { Self() }
}
enum ShadowrocketAccess {
    static var host = "8.8.4.4"
    static func readCurrent() throws -> ShadowrocketProfile {
        ShadowrocketProfile(selection: "fixture", host: host, port: 443, transport: "tcp", security: .tls)
    }
}
extension DetectedEndpoint {
    static func observe(host: String) -> [Self] { [] }
}
enum Tools {
    struct Result { let code: Int32; let text: String }
    static func call(_ executable: String, _ args: [String]) -> Result {
        preconditionFailure("Sealed migration attempted ordinary-user networking")
    }
}

@main enum MigrationFixture {
    static func main() throws {
        let store = try GuardianStore()
        let route = GuardianRoute(interface: "utun6", peer: "8.8.4.4", port: "443", transport: "tcp",
                                  expected: "8.8.8.8", region: "US", adminSource: "")
        let service = UUID().uuidString
        let path = store.directory + "/intent.json"
        let fence = try GuardianPacketFence.fixture(directory: store.directory, pf: "/no-pf-must-run")
        let core = GuardianCore(store: store, fence: fence)
        for (schema, policy) in [(1, "ipv4-tunnel-v7"), (2, "ipv4-tunnel-v8")] {
            for pinned in [true, false] {
                var legacy = GuardianIntent()
                legacy.ownerUID = getuid()
                legacy.maintenance = true
                legacy.approved = true
                legacy.persistent = true
                legacy.mode = "live"
                legacy.session = UUID().uuidString
                legacy.bootID = GuardianStore.bootID()!
                legacy.route = route
                legacy.bootstrapHost = route.peer
                legacy.serviceID = pinned ? service : nil
                var object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(legacy)) as! [String: Any]
                object["schemaVersion"] = schema
                object["policy"] = policy
                try JSONSerialization.data(withJSONObject: object).write(to: URL(fileURLWithPath: path))
                precondition(chmod(path, 0o600) == 0)
                try store.locked { try store.migrateLegacy(owner: getuid()) }
                let migrated = try store.locked { try store.read() }
                precondition(migrated.maintenance && !migrated.armed && !migrated.approved)
                precondition(migrated.serviceID == (pinned ? service : nil) && migrated.riskKey == nil)
                precondition(migrated.profileFingerprint == nil && migrated.automaticEnabled == false)
                let box = GuardianReplyBox()
                core.submit(GuardianRequest(.state), uid: getuid(), authorization: Data(), recoveryOnly: false) { box.finish($0) }
                precondition(box.semaphore.wait(timeout: .now() + 5) == .success)
                let state = box.result()
                precondition(state.code == 0 && state.active && !state.canResume && !state.paused)
                precondition(state.revalidationRoute == route && state.profileFingerprint == nil)
                let discovered = try AutomaticRoute.read(region: "US", revalidation: state.revalidationRoute)
                precondition(discovered.route == route)
                ShadowrocketAccess.host = "9.9.9.9"
                do {
                    _ = try AutomaticRoute.read(region: "US", revalidation: state.revalidationRoute)
                    preconditionFailure("Changed migration node accepted")
                } catch AutomaticRoute.Failure.bootstrapChanged {}
                ShadowrocketAccess.host = route.peer
                object["serviceID"] = "invalid-service"
                try JSONSerialization.data(withJSONObject: object).write(to: URL(fileURLWithPath: path))
                do {
                    try store.locked { try store.migrateLegacy(owner: getuid()) }
                    preconditionFailure("Malformed legacy service accepted")
                } catch GuardianStore.Failure.corrupt {}
            }
        }
        print("PASS: v7/v8 migration through actual Core state and discovery, pinned/unpinned sealed bootstrap, revoked approvals, changed-node and malformed-service rejection without ordinary networking")
    }
}
