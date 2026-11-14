import Darwin
import Foundation

// Synthetic root-only trust for the isolated engineering supervisor. Production
// signing/XPC trust is verified separately and this file is never shipped.
struct GuardianTrust {
    static let directory = "/Library/PrivilegedHelperTools/org.claudeguard.acceptance/core"
    let ownerUID: UInt32 = 0
    static func load() -> Self? { Self() }
    func requirement(_ identifier: String) -> String? { nil }
}
