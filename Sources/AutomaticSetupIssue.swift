import Foundation

enum AutomaticSetupIssue: String {
    case profileAccess, profileInvalid, profileAmbiguous, profileUnsupported, profileChanged
    case routingMode, numericBootstrap, disconnected, tunnelRoute, probeResponse, providerEndpoint, pathChanged, bootstrapChanged, unknown

    init(_ error: Error) {
        switch error {
        case ShadowrocketProfile.Failure.unavailable: self = .profileAccess
        case ShadowrocketProfile.Failure.invalid: self = .profileInvalid
        case ShadowrocketProfile.Failure.ambiguous: self = .profileAmbiguous
        case ShadowrocketProfile.Failure.unsupported: self = .profileUnsupported
        case ShadowrocketProfile.Failure.changed: self = .profileChanged
        case ShadowrocketProfile.Failure.routing: self = .routingMode
        case ShadowrocketProfile.Failure.bootstrap: self = .numericBootstrap
        case AutomaticRoute.Failure.disconnected: self = .disconnected
        case AutomaticRoute.Failure.route: self = .tunnelRoute
        case AutomaticRoute.Failure.response: self = .probeResponse
        case AutomaticRoute.Failure.endpoint: self = .providerEndpoint
        case AutomaticRoute.Failure.changed: self = .pathChanged
        case AutomaticRoute.Failure.bootstrapChanged: self = .bootstrapChanged
        default: self = .unknown
        }
    }

    var message: GuardText {
        switch self {
        case .profileAccess:
            return GuardText("Allow read access to the Shadowrocket configuration folder, then detect again.")
        case .profileInvalid:
            return GuardText("The Shadowrocket configuration format could not be validated. Protection setup is blocked.")
        case .profileAmbiguous:
            return GuardText("The selected Shadowrocket profile is ambiguous. Protection setup is blocked.")
        case .profileUnsupported:
            return GuardText("The selected profile's transport or encryption settings are not supported for automatic protection.")
        case .profileChanged:
            return GuardText("The selected profile changed during detection. A fresh check is required.")
        case .routingMode:
            return GuardText("Set Shadowrocket Global Routing to Proxy. Config and Direct modes are not admitted automatically.")
        case .numericBootstrap:
            return GuardText("Use a dedicated node profile with a numeric IPv4 server address. Hostname bootstrap cannot recover with outside DNS blocked.")
        case .disconnected:
            return GuardText("Connect Shadowrocket before automatic protection can be activated.")
        case .tunnelRoute:
            return GuardText("The active VPN route could not be confirmed. Protection setup is blocked.")
        case .probeResponse:
            return GuardText("The tunnel exit check did not return valid evidence. Automatic detection will retry.")
        case .providerEndpoint:
            return GuardText("A unique live connection from the verified Shadowrocket provider could not be confirmed.")
        case .pathChanged:
            return GuardText("The VPN path changed during detection. A fresh check is required.")
        case .bootstrapChanged:
            return GuardText("The selected node differs from the sealed bootstrap. Restore networking locally before approving a different node.")
        case .unknown:
            return GuardText("Automatic setup could not be completed. Check the protection status before continuing.")
        }
    }
}
