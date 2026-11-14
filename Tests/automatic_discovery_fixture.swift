import Foundation

// Only operating-system observations are supplied by the fixture. The actual
// discovery, metadata types, route validation and response schema are compiled.
let guardSigningTeam = ""
struct GuardConfiguration {
    static func validInterface(_ value: String) -> Bool {
        value.range(of: #"^utun[0-9]+\z"#, options: .regularExpression) != nil
    }
}
struct LocalCheck {
    var vpnConnected: Bool
    var defaultInterface: String
    static var current = LocalCheck(vpnConnected: true, defaultInterface: "utun6")
    static func read() -> Self { current }
}
enum ShadowrocketAccess {
    static var current = ShadowrocketProfile(selection: "fixture", host: "8.8.4.4", port: 443, transport: "tcp", security: .tls)
    static var reads = 0
    static var mutateOnSecondRead = false
    static func readCurrent() throws -> ShadowrocketProfile {
        reads += 1
        if mutateOnSecondRead && reads == 2 {
            return ShadowrocketProfile(selection: "changed", host: current.host, port: current.port, transport: current.transport, security: current.security)
        }
        return current
    }
}
extension DetectedEndpoint {
    static var fixtureEndpoints = [DetectedEndpoint(host: "8.8.4.4", port: 443, transport: "tcp")]
    static func observe(host: String) -> [Self] { fixtureEndpoints }
}
enum Tools {
    struct Result { let code: Int32; let text: String }
    static var calls = 0
    static var allowNetwork = false
    static func call(_ executable: String, _ args: [String]) -> Result {
        calls += 1
        precondition(allowNetwork, "Sealed revalidation attempted ordinary-user networking")
        precondition(executable == "/usr/bin/curl" && args.contains("if!utun6") && args.contains("--noproxy"))
        return Result(code: 0, text: "ip=8.8.8.8\nloc=US\n\n200")
    }
}

@main enum AutomaticDiscoveryFixture {
    static func rejects(_ expected: AutomaticRoute.Failure, _ body: () throws -> AutomaticRoute) {
        do { _ = try body(); preconditionFailure("Unexpected discovery approval") }
        catch let error as AutomaticRoute.Failure { precondition(String(describing: error) == String(describing: expected)) }
        catch { preconditionFailure("Unexpected error type") }
    }

    static func main() throws {
        Tools.allowNetwork = true
        let initial = try AutomaticRoute.read(region: "US")
        precondition(initial.route.expected == "8.8.8.8" && Tools.calls == 1)
        Tools.allowNetwork = false
        Tools.calls = 0
        DetectedEndpoint.fixtureEndpoints = []
        LocalCheck.current = LocalCheck(vpnConnected: false, defaultInterface: "en0")
        rejects(.disconnected) { try AutomaticRoute.read(region: "US") }
        // A disconnected provider can restart only with root-returned context
        // for its previously pinned node. No user-process TLS or socket fallback.
        let sealed = try AutomaticRoute.read(region: "US", revalidation: initial.route)
        precondition(sealed.route == initial.route && Tools.calls == 0)
        LocalCheck.current = LocalCheck(vpnConnected: true, defaultInterface: "utun9")
        let newInterface = try AutomaticRoute.read(region: "US", revalidation: initial.route)
        precondition(newInterface.route.interface == "utun9" && Tools.calls == 0)
        var changed = initial.route
        changed.peer = "9.9.9.9"
        rejects(.bootstrapChanged) { try AutomaticRoute.read(region: "US", revalidation: changed) }
        changed = initial.route
        changed.port = "8443"
        rejects(.bootstrapChanged) { try AutomaticRoute.read(region: "US", revalidation: changed) }
        changed = initial.route
        changed.transport = "udp"
        rejects(.bootstrapChanged) { try AutomaticRoute.read(region: "US", revalidation: changed) }
        changed = initial.route
        changed.expected = "127.0.0.1"
        rejects(.bootstrapChanged) { try AutomaticRoute.read(region: "US", revalidation: changed) }
        rejects(.bootstrapChanged) { try AutomaticRoute.read(region: "GB", revalidation: initial.route) }
        ShadowrocketAccess.reads = 0
        ShadowrocketAccess.mutateOnSecondRead = true
        rejects(.changed) { try AutomaticRoute.read(region: "US", revalidation: initial.route) }
        precondition(Tools.calls == 0)
        print("PASS: actual automatic discovery, connected initial control, same-node sealed/offline revalidation without ordinary networking, interface renewal, changed endpoint/region rejection and metadata race")
    }
}
