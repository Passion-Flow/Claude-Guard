import Foundation

struct AutomaticRoute: Sendable {
    let profile: ShadowrocketProfile
    let route: GuardianRoute

    enum Failure: Error { case disconnected, route, response, endpoint, changed, bootstrapChanged }

    static func read(region: String, revalidation: GuardianRoute? = nil) throws -> Self {
        let before = LocalCheck.read()
        let profile = try ShadowrocketAccess.readCurrent()
        guard publicAddress(profile.host) else { throw Failure.endpoint }
        if var pinned = revalidation {
            guard pinned.valid, publicAddress(pinned.expected), pinned.region == region,
                  pinned.peer == profile.host, pinned.port == String(profile.port),
                  pinned.transport == profile.transport else { throw Failure.bootstrapChanged }
            if before.vpnConnected, GuardConfiguration.validInterface(before.defaultInterface) {
                pinned.interface = before.defaultInterface
            }
            guard try ShadowrocketAccess.readCurrent() == profile else { throw Failure.changed }
            // Ordinary-user HTTPS is deliberately blocked in LOCKED and SEALED.
            // Reuse only root-owned bootstrap context for the exact same node.
            // Activation still needs fresh root identity, stability and risk evidence.
            return Self(profile: profile, route: pinned)
        }
        guard before.vpnConnected else { throw Failure.disconnected }
        let interface = before.defaultInterface
        guard GuardConfiguration.validInterface(interface) else { throw Failure.route }
        let addresses: Set<String> = [profile.host]
        let candidates = addresses.flatMap { DetectedEndpoint.observe(host: $0) }
            .filter { $0.port == profile.port && $0.transport == profile.transport }
        guard Set(candidates).count == 1, let endpoint = candidates.first else { throw Failure.endpoint }
        let trace = try fetch("https://1.1.1.1/cdn-cgi/trace", interface: interface)
        guard let text = String(data: trace, encoding: .utf8), !text.contains("\0"), text.utf8.count <= 4096 else { throw Failure.response }
        let exits = text.split(separator: "\n").filter { $0.hasPrefix("ip=") }.map { String($0.dropFirst(3)) }
        guard exits.count == 1, let exit = exits.first, publicAddress(exit) else { throw Failure.response }
        let after = LocalCheck.read()
        guard after.vpnConnected, after.defaultInterface == interface,
              try ShadowrocketAccess.readCurrent() == profile else { throw Failure.changed }
        let route = GuardianRoute(interface: interface, peer: endpoint.host, port: String(endpoint.port),
                                  transport: endpoint.transport, expected: exit, region: region, adminSource: "")
        guard route.valid else { throw Failure.route }
        return Self(profile: profile, route: route)
    }

    private static func publicAddress(_ value: String) -> Bool {
        guard DetectedEndpoint.validIPv4(value) else { return false }
        let p = value.split(separator: ".").compactMap { Int($0) }
        return !([0, 10, 127].contains(p[0]) || p[0] >= 224 ||
            (p[0] == 100 && (64...127).contains(p[1])) ||
            (p[0] == 169 && p[1] == 254) || (p[0] == 172 && (16...31).contains(p[1])) ||
            (p[0] == 192 && [0, 168].contains(p[1])) || (p[0] == 198 && [18, 19].contains(p[1])) ||
            (p[0] == 198 && p[1] == 51 && p[2] == 100) || (p[0] == 203 && p[1] == 0 && p[2] == 113))
    }

    private static func fetch(_ url: String, interface: String, additional: [String] = []) throws -> Data {
        let result = Tools.call("/usr/bin/curl", ["-q", "-4", "--noproxy", "*", "--interface", "if!" + interface,
            "--proto", "=https", "--tlsv1.2", "--connect-timeout", "2", "--max-time", "4",
            "--max-filesize", "16384", "-fsS", "--write-out", "\n%{http_code}"] + additional + [url])
        guard result.code == 0, result.text.hasSuffix("\n200"), result.text.utf8.count <= 16388 else { throw Failure.response }
        return Data(result.text.dropLast(4).utf8)
    }
}
