import AppKit
import Foundation
import Security

/// Loads the vendor app once in the login session when a previously approved
/// persistent route needs recovery. It never changes network permission.
@MainActor
final class ShadowrocketStartup {
    private var attempted = false
    private static let identifier = "com.liguangming.Shadowrocket"
    nonisolated private static let requirement = """
    anchor apple generic and identifier "com.liguangming.Shadowrocket" and (
      certificate leaf[field.1.2.840.113635.100.6.1.9] exists or (
        certificate 1[field.1.2.840.113635.100.6.2.6] exists and
        certificate leaf[field.1.2.840.113635.100.6.1.13] exists and
        certificate leaf[subject.OU] = "JBJ55K5C9X"
      )
    )
    """

    static func allowed(profile: ShadowrocketProfile, route: GuardianRoute?, fingerprint: String?,
                        active: Bool, persistent: Bool, automatic: Bool, paused: Bool, open: Bool) -> Bool {
        guard active, persistent, automatic, !paused, !open, let route, route.valid,
              fingerprint == profile.fingerprint,
              route.peer == profile.host, route.port == String(profile.port),
              route.transport == profile.transport else { return false }
        return true
    }

    func prepare(profile: ShadowrocketProfile, route: GuardianRoute?, fingerprint: String?,
                 active: Bool, persistent: Bool, automatic: Bool, paused: Bool, open: Bool,
                 stillCurrent: @escaping @MainActor () -> Bool) async {
        guard !attempted, Self.allowed(profile: profile, route: route, fingerprint: fingerprint,
            active: active, persistent: persistent, automatic: automatic, paused: paused, open: open) else { return }
        attempted = true
        guard NSRunningApplication.runningApplications(withBundleIdentifier: Self.identifier).isEmpty else { return }
        let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: Self.identifier)
            ?? URL(fileURLWithPath: "/Applications/Shadowrocket.app", isDirectory: true)
        let valid = await Task.detached { Self.validApplication(at: url) }.value
        guard valid, stillCurrent(),
              (try? ShadowrocketAccess.readCurrent()) == profile else { return }
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = false
        configuration.hides = true
        configuration.addsToRecentItems = false
        // The root worker already retains the physical seal and retries only
        // its pinned service. Opening the app merely makes its extension
        // available in this user's login session.
        NSWorkspace.shared.openApplication(at: url, configuration: configuration) { _, _ in }
    }

    nonisolated private static func validApplication(at url: URL) -> Bool {
        var code: SecStaticCode?
        var requirement: SecRequirement?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
              let code,
              SecRequirementCreateWithString(Self.requirement as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return false }
        return SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), requirement) == errSecSuccess
    }

    #if GUARD_DIAGNOSTICS
    static func selfTest() -> Bool {
        let profile = ShadowrocketProfile(selection: "fixture", host: "192.0.2.42", port: 443,
                                         transport: "tcp", security: .tls)
        let route = GuardianRoute(interface: "utun6", peer: profile.host, port: "443", transport: "tcp",
                                  expected: "192.0.2.43", region: "US", adminSource: "")
        func check(_ route: GuardianRoute? = route, fingerprint: String? = profile.fingerprint,
                   active: Bool = true, persistent: Bool = true, automatic: Bool = true,
                   paused: Bool = false, open: Bool = false) -> Bool {
            allowed(profile: profile, route: route, fingerprint: fingerprint, active: active,
                    persistent: persistent, automatic: automatic, paused: paused, open: open)
        }
        var other = route
        other.peer = "192.0.2.44"
        return check() && !check(nil) && !check(other) && !check(fingerprint: nil) &&
            !check(fingerprint: "different") && !check(active: false) && !check(persistent: false) &&
            !check(automatic: false) && !check(paused: true) && !check(open: true)
    }
    #endif
}
