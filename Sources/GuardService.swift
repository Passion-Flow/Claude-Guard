import Foundation
import Security

enum GuardianWire { static let version = 2 }

struct GuardianRoute: Codable, Equatable {
    var interface: String
    var peer: String
    var port: String
    var transport: String
    var expected: String
    var region: String
    var adminSource: String
    var developmentPeer: String? = nil

    var endpointKey: String { peer + ":" + port + "/" + transport }
    var valid: Bool {
        interface.range(of: #"^utun[0-9]+\z"#, options: .regularExpression) != nil &&
            DetectedEndpoint.validIPv4(peer) && DetectedEndpoint.validIPv4(expected) &&
            !["1.1.1.1", "1.0.0.1"].contains(peer) &&
            UInt16(port).map { $0 > 0 && String($0) == port } == true &&
            ["tcp", "udp"].contains(transport) && GuardRiskPolicy.regions.contains(region) &&
            adminSource.isEmpty && (developmentPeer == nil || Self.validDevelopmentPeer(developmentPeer!))
    }

    static func validDevelopmentPeer(_ address: String) -> Bool {
        guard DetectedEndpoint.validIPv4(address) else { return false }
        let parts = address.split(separator: ".").compactMap { Int($0) }
        return parts[0] == 100 && (64...127).contains(parts[1])
    }

    func matches(_ link: String) -> Bool {
        guard link.utf8.count <= 8192, let endpoint = DetectedEndpoint.parseShareLink(link),
              endpoint.id == endpointKey else { return false }
        return !TransportEvidence.inspect(link, endpoint: endpoint).kind.blocksActivation
    }
}

struct GuardianRequest: Codable {
    enum Operation: String, Codable { case hello, state, activate, invalidate, trial, resume, commit, pause, restore }
    var operation: Operation
    var session: String?
    var route: GuardianRoute?
    var riskKey: String?
    var nodeLink: String?
    var profileEvidence: TransportEvidence?
    var profileFingerprint: String?
    var profileServer: String?
    var controlRevision: String?
    var userInitiated: Bool?

    init(_ operation: Operation, session: String? = nil, route: GuardianRoute? = nil,
         riskKey: String? = nil, nodeLink: String? = nil,
         profileEvidence: TransportEvidence? = nil, profileFingerprint: String? = nil, profileServer: String? = nil,
         controlRevision: String? = nil, userInitiated: Bool? = nil) {
        self.operation = operation
        self.session = session
        self.route = route
        self.riskKey = riskKey
        self.nodeLink = nodeLink
        self.profileEvidence = profileEvidence
        self.profileFingerprint = profileFingerprint
        self.profileServer = profileServer
        self.controlRevision = controlRevision
        self.userInitiated = userInitiated
    }
}

struct GuardianResponse: Codable {
    var code: Int32
    var wireVersion = GuardianWire.version
    var active = false
    var persistent = false
    var canResume = false
    var workerAlive = false
    var paused = false
    var automaticEnabled = true
    var controlRevision: String?
    var status: String?
    var journal: String?
    var profileFingerprint: String?
    var revalidationRoute: GuardianRoute?
}

final class GuardianReplyBox {
    let semaphore = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var value: GuardianResponse?

    func finish(_ response: GuardianResponse) {
        lock.lock()
        defer { lock.unlock() }
        guard value == nil else { return }
        value = response
        semaphore.signal()
    }

    func result() -> GuardianResponse {
        lock.lock()
        defer { lock.unlock() }
        return value ?? GuardianResponse(code: 74)
    }
}

@objc protocol GuardianProtocol {
    func submit(_ request: Data, authorization: Data, withReply reply: @escaping (Data) -> Void)
}

enum GuardianIdentity {
    static let application = "org.claudeguard.mac"
    static let daemon = "org.claudeguard.daemon"
    static let recoveryDaemon = "org.claudeguard.offline-recovery"
    static let recoveryChannel = "org.claudeguard.daemon.recovery"

    static func requirement(_ identifier: String) -> String? {
        guard [application, daemon, recoveryDaemon].contains(identifier) else { return nil }
        let expression: String
        if guardSigningTeam.isEmpty {
            guard let pinned = GuardianTrust.load()?.requirement(identifier) else { return nil }
            expression = pinned
        } else {
            guard guardSigningTeam.utf8.count == 10,
                  guardSigningTeam.utf8.allSatisfy({ (65...90).contains($0) || (48...57).contains($0) }) else { return nil }
            expression = """
        anchor apple generic and identifier "\(identifier)" and \
        certificate 1[field.1.2.840.113635.100.6.2.6] exists and \
        certificate leaf[field.1.2.840.113635.100.6.1.13] exists and \
        certificate leaf[subject.OU] = "\(guardSigningTeam)"
        """
        }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(expression as CFString, [], &requirement) == errSecSuccess else { return nil }
        return expression
    }

    static func currentProcessMatches(_ identifier: String) -> Bool {
        guard let text = requirement(identifier) else { return false }
        var requirement: SecRequirement?
        var code: SecCode?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              SecCodeCopySelf([], &code) == errSecSuccess,
              code.map({ SecCodeCheckValidity($0, [], requirement) == errSecSuccess }) == true else { return false }
        if identifier == application {
            let expected = "/Applications/Claude Guard.app"
            guard Bundle.main.bundleURL.resolvingSymlinksInPath().path == expected else { return false }
            var installed: SecStaticCode?
            return SecStaticCodeCreateWithPath(Bundle.main.bundleURL as CFURL, [], &installed) == errSecSuccess && installed.map {
                SecStaticCodeCheckValidity($0, SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate), requirement) == errSecSuccess
            } == true
        }
        return true
    }
}

enum GuardianAuthorization {
    private static let right = "system.privilege.admin"

    static func withExternalForm<Result>(_ body: (Data) -> Result) -> Result? {
        var reference: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &reference) == errAuthorizationSuccess, let reference else { return nil }
        defer { AuthorizationFree(reference, [.destroyRights]) }
        guard validate(reference, flags: [.interactionAllowed, .extendRights]) else { return nil }
        var form = AuthorizationExternalForm()
        guard AuthorizationMakeExternalForm(reference, &form) == errAuthorizationSuccess else { return nil }
        return withUnsafeBytes(of: &form) { body(Data($0)) }
    }

    static func validate(_ data: Data) -> Bool {
        var form = AuthorizationExternalForm()
        guard data.count == MemoryLayout.size(ofValue: form) else { return false }
        _ = withUnsafeMutableBytes(of: &form) { data.copyBytes(to: $0) }
        var reference: AuthorizationRef?
        guard AuthorizationCreateFromExternalForm(&form, &reference) == errAuthorizationSuccess, let reference else { return false }
        defer { AuthorizationFree(reference, []) }
        return validate(reference, flags: [])
    }

    private static func validate(_ reference: AuthorizationRef, flags: AuthorizationFlags) -> Bool {
        right.withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { pointer in
                var rights = AuthorizationRights(count: 1, items: pointer)
                return AuthorizationCopyRights(reference, &rights, nil, flags, nil) == errAuthorizationSuccess
            }
        }
    }
}
