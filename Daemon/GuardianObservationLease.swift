import Foundation

/// Revocation-only supervision of worker-validated evidence. Publications and
/// repeated reads cannot extend either observation lifetime. Network admission
/// remains the worker's responsibility behind the native packet fence.
struct GuardianObservationLease {
    private var context: String?
    private var observation: TimeInterval = 0
    private var observationOrigin: TimeInterval = 0
    private var risk: TimeInterval = 0
    private var riskOrigin: TimeInterval = 0

    /// Evidence is published before the legacy UI status. A newer restrictive
    /// publication is authoritative during that small cross-file transition;
    /// it never grants OPEN or renews the remembered observation clocks.
    static func restrictivePublication(_ text: String, session: String, service: String,
                                       endpoint: String, expected: String, wall: TimeInterval) -> Bool {
        let line = text.hasSuffix("\n") ? String(text.dropLast()) : text
        let fields = line.components(separatedBy: "|")
        guard !line.contains("\n"), !line.contains("\r"), fields.count == 11,
              fields[0] == "1", fields[1] == session, fields[7] == service,
              fields[8] == endpoint, fields[9] == expected,
              ["LOCKED", "VERIFYING", "DRIFT", "ERROR"].contains(fields[2]),
              fields[3].utf8.allSatisfy({ (48...57).contains($0) }),
              (1...12).contains(fields[3].utf8.count), fields[3].first != "0",
              let published = Double(fields[3]), wall.isFinite,
              (0..<12).contains(wall - published) else { return false }
        return true
    }

    mutating func accepts(_ text: String, session: String, service: String, interface: String,
                          endpoint: String, expected: String, wall: TimeInterval,
                          uptime: TimeInterval) -> Bool {
        let line = text.hasSuffix("\n") ? String(text.dropLast()) : text
        let fields = line.components(separatedBy: "|")
        guard !line.contains("\n"), !line.contains("\r"), fields.count == 11,
              UUID(uuidString: session) != nil, UUID(uuidString: service) != nil,
              interface.hasPrefix("utun"), (5...10).contains(interface.utf8.count),
              interface.dropFirst(4).utf8.allSatisfy({ (48...57).contains($0) }),
              fields[0] == "1", fields[1] == session, ["OPEN", "ADMITTING"].contains(fields[2]),
              fields[6] == interface, fields[7] == service, fields[8] == endpoint,
              fields[9] == expected, fields[10] == "1",
              wall.isFinite, uptime.isFinite, uptime >= 0 else { return false }
        func timestamp(_ value: String) -> TimeInterval? {
            guard !value.isEmpty, value.utf8.count <= 12,
                  value.utf8.allSatisfy({ (48...57).contains($0) }),
                  value == "0" || value.first != "0", let stamp = Double(value), stamp > 0 else { return nil }
            return stamp
        }
        guard let published = timestamp(fields[3]), let observed = timestamp(fields[4]),
              let reviewed = timestamp(fields[5]), published >= observed, published >= reviewed,
              (0..<12).contains(wall - published), (0..<12).contains(wall - observed),
              (0..<3600).contains(wall - reviewed) else { return false }
        let key = [session, service, interface, endpoint, expected].joined(separator: "|")
        if context != key {
            context = key
            observation = 0
            risk = 0
        }
        guard observed >= observation, reviewed >= risk else { return false }
        if observed > observation {
            observation = observed
            // Subtract age on first observation; polling delay is not a new
            // lease and wall-clock rollback cannot renew the saved origin.
            observationOrigin = uptime - (wall - observed)
        }
        if reviewed > risk {
            risk = reviewed
            riskOrigin = uptime - (wall - reviewed)
        }
        return (0..<12).contains(uptime - observationOrigin) &&
            (0..<3600).contains(uptime - riskOrigin)
    }
}
