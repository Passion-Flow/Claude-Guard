import Foundation

enum GuardRiskPolicy {
    enum Decision: Int32 { case accepted = 0, rejected = 1, unavailable = 2 }

    static let regions = Locale.Region.isoRegions.map(\.identifier).filter {
        $0.utf8.count == 2 && $0.utf8.allSatisfy { (65...90).contains($0) } &&
            !["CN", "EU", "UN", "XX", "ZZ"].contains($0)
    }.sorted()

    static func validKey(_ value: String) -> Bool {
        (16...128).contains(value.utf8.count) && value.utf8.allSatisfy {
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95
        }
    }

    private struct Response: Decodable {
        let success: Bool
        let fraudScore: Int
        let connectionType: String
        let countryCode: String
        let proxy: Bool
        let vpn: Bool
        let tor: Bool
        let activeVPN: Bool
        let activeTor: Bool
        let recentAbuse: Bool
        let botStatus: Bool

        enum CodingKeys: String, CodingKey {
            case success, proxy, vpn, tor
            case fraudScore = "fraud_score"
            case connectionType = "connection_type"
            case countryCode = "country_code"
            case activeVPN = "active_vpn"
            case activeTor = "active_tor"
            case recentAbuse = "recent_abuse"
            case botStatus = "bot_status"
        }
    }

    static func evaluate(_ data: Data, region: String) -> Decision {
        guard regions.contains(region), data.count <= 16384, uniqueTopLevelKeys(data),
              let response = try? JSONDecoder().decode(Response.self, from: data), response.success,
              (0...100).contains(response.fraudScore),
              Locale.Region.isoRegions.contains(where: { $0.identifier == response.countryCode }),
              !response.connectionType.isEmpty, response.connectionType != "N/A" else { return .unavailable }
        guard response.countryCode == region, response.connectionType == "Residential", response.fraudScore <= 10,
              !response.proxy, !response.vpn, !response.tor, !response.activeVPN,
              !response.activeTor, !response.recentAbuse, !response.botStatus else { return .rejected }
        return .accepted
    }

    private static func uniqueTopLevelKeys(_ data: Data) -> Bool {
        struct Frame { var object: Bool; var expectsKey: Bool; var keys = Set<String>() }
        let bytes = [UInt8](data)
        var index = 0
        var frames: [Frame] = []
        while index < bytes.count {
            switch bytes[index] {
            case 123, 91:
                guard frames.count < 32 else { return false }
                frames.append(Frame(object: bytes[index] == 123, expectsKey: bytes[index] == 123))
            case 125, 93:
                guard !frames.isEmpty else { return false }
                frames.removeLast()
            case 44:
                if !frames.isEmpty, frames[frames.count - 1].object { frames[frames.count - 1].expectsKey = true }
            case 58:
                if !frames.isEmpty { frames[frames.count - 1].expectsKey = false }
            case 34:
                let start = index
                index += 1
                var escaped = false
                while index < bytes.count {
                    let byte = bytes[index]
                    if escaped { escaped = false }
                    else if byte == 92 { escaped = true }
                    else if byte == 34 { break }
                    index += 1
                }
                guard index < bytes.count else { return false }
                if !frames.isEmpty && frames[frames.count - 1].object && frames[frames.count - 1].expectsKey {
                    guard let key = try? JSONDecoder().decode(String.self, from: Data(bytes[start...index])),
                          frames[frames.count - 1].keys.insert(key).inserted else { return false }
                    frames[frames.count - 1].expectsKey = false
                }
            default: break
            }
            index += 1
        }
        return frames.isEmpty
    }

    private struct KeylessRecord: Decodable {
        struct Network: Decodable { let type: String }
        struct Detections: Decodable {
            let proxy: Bool
            let vpn: Bool
            let tor: Bool
            let hosting: Bool
            let anonymous: Bool
            let compromised: Bool
            let scraper: Bool
            let risk: Int
            let confidence: Int
        }
        let network: Network
        let detections: Detections
        let lastUpdated: String
        enum CodingKeys: String, CodingKey {
            case network, detections
            case lastUpdated = "last_updated"
        }
    }

    static func evaluateKeyless(_ data: Data, region: String, expected: String, observedRegion: String) -> Decision {
        guard regions.contains(region), DetectedEndpoint.validIPv4(expected),
              observedRegion.utf8.count == 2 else { return .unavailable }
        guard observedRegion == region else { return .rejected }
        guard data.count <= 16384, uniqueTopLevelKeys(data),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              root["status"] as? String == "ok", let row = root[expected] as? [String: Any],
              let recordData = try? JSONSerialization.data(withJSONObject: row),
              let record = try? JSONDecoder().decode(KeylessRecord.self, from: recordData),
              (0...100).contains(record.detections.risk), (0...100).contains(record.detections.confidence),
              let updated = ISO8601DateFormatter().date(from: record.lastUpdated),
              updated.timeIntervalSinceNow <= 300 else { return .unavailable }
        // Provider confidence measures positive detections, not confidence
        // that a line is clean. Keep its type/range validation above, and
        // never use a low value to waive any positive risk flag below.
        let flags = record.detections
        guard record.network.type == "Residential", flags.risk <= 10,
              !flags.proxy, !flags.vpn, !flags.tor, !flags.hosting,
              !flags.anonymous, !flags.compromised, !flags.scraper else { return .rejected }
        return .accepted
    }

    static func keylessSelfTest() -> Bool {
        let ip = "192.0.2.42"
        var flags: [String: Any] = ["proxy": false, "vpn": false, "tor": false, "hosting": false,
                                   "anonymous": false, "compromised": false, "scraper": false, "risk": 0, "confidence": 100]
        func data() -> Data {
            (try? JSONSerialization.data(withJSONObject: ["status": "ok", ip: ["network": ["type": "Residential"],
                "detections": flags, "last_updated": ISO8601DateFormatter().string(from: Date())]])) ?? Data()
        }
        guard evaluateKeyless(data(), region: "US", expected: ip, observedRegion: "US") == .accepted,
              evaluateKeyless(data(), region: "US", expected: ip, observedRegion: "CN") == .rejected,
              evaluateKeyless(data(), region: "US", expected: "192.0.2.99", observedRegion: "US") == .unavailable else { return false }
        for flag in ["proxy", "vpn", "tor", "hosting", "anonymous", "compromised", "scraper"] {
            flags[flag] = true
            guard evaluateKeyless(data(), region: "US", expected: ip, observedRegion: "US") == .rejected else { return false }
            flags[flag] = "false"
            guard evaluateKeyless(data(), region: "US", expected: ip, observedRegion: "US") == .unavailable else { return false }
            flags[flag] = false
        }
        flags["risk"] = 11
        guard evaluateKeyless(data(), region: "US", expected: ip, observedRegion: "US") == .rejected else { return false }
        flags["risk"] = 0
        for confidence in [0, 25, 89, 100] {
            flags["confidence"] = confidence
            guard evaluateKeyless(data(), region: "US", expected: ip, observedRegion: "US") == .accepted else { return false }
            flags["proxy"] = true
            guard evaluateKeyless(data(), region: "US", expected: ip, observedRegion: "US") == .rejected else { return false }
            flags["proxy"] = false
        }
        for confidence in ([-1, 101, "100", true, NSNull()] as [Any]) {
            flags["confidence"] = confidence
            guard evaluateKeyless(data(), region: "US", expected: ip, observedRegion: "US") == .unavailable else { return false }
        }
        flags.removeValue(forKey: "confidence")
        guard evaluateKeyless(data(), region: "US", expected: ip, observedRegion: "US") == .unavailable else { return false }
        flags["confidence"] = 100
        let text = String(decoding: data(), as: UTF8.self).replacingOccurrences(of: "\"proxy\":false", with: "\"proxy\":false,\"proxy\":false")
        return evaluateKeyless(Data(text.utf8), region: "US", expected: ip, observedRegion: "US") == .unavailable
    }

    static func selfTest() -> Bool {
        var fields: [String: Any] = ["success": true, "fraud_score": 0, "connection_type": "Residential",
                                     "country_code": "US", "proxy": false, "vpn": false, "tor": false,
                                     "active_vpn": false, "active_tor": false, "recent_abuse": false, "bot_status": false]
        func decision() -> Decision {
            guard let data = try? JSONSerialization.data(withJSONObject: fields) else { return .unavailable }
            return evaluate(data, region: "US")
        }
        guard decision() == .accepted, validKey("FixtureRiskKey0123456789"), !validKey("unsafe\nkey") else { return false }
        guard let encoded = try? JSONSerialization.data(withJSONObject: fields),
              let text = String(data: encoded, encoding: .utf8),
              evaluate(Data((text.dropLast() + ",\"fraud_score\":0}").utf8), region: "US") == .unavailable,
              evaluate(Data((text.dropLast() + #", "fraud_\u0073core": 0}"#).utf8), region: "US") == .unavailable else { return false }
        for flag in ["proxy", "vpn", "tor", "active_vpn", "active_tor", "recent_abuse", "bot_status"] {
            fields[flag] = true
            guard decision() == .rejected else { return false }
            fields[flag] = "false"
            guard decision() == .unavailable else { return false }
            fields[flag] = false
        }
        fields["fraud_score"] = 11
        guard decision() == .rejected else { return false }
        fields["fraud_score"] = -1
        guard decision() == .unavailable else { return false }
        fields["fraud_score"] = 0
        fields["country_code"] = "CA"
        guard decision() == .rejected else { return false }
        fields.removeValue(forKey: "country_code")
        return decision() == .unavailable
    }
}
