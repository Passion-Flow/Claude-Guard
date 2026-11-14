import Foundation

struct DetectedEndpoint: Hashable, Identifiable, Sendable {
    let host: String
    let port: UInt16
    let transport: String

    var id: String { host + ":" + String(port) + "/" + transport }
    var label: String { host + ":" + String(port) + " · " + transport.uppercased() }

    static func validIPv4(_ value: String) -> Bool {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy {
            guard let byte = UInt8($0), String(byte) == $0 else { return false }
            return true
        }
    }

    static func parseShareLink(_ input: String) -> Self? {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.utf8.count <= 8192,
              let url = URLComponents(string: value),
              let scheme = url.scheme?.lowercased(),
              let host = url.host, validIPv4(host),
              let rawPort = url.port, let port = UInt16(exactly: rawPort), port > 0 else { return nil }

        let params = url.queryItems ?? []
        guard !params.contains(where: { ["mport", "udphop", "ports"].contains($0.name.lowercased()) }) else { return nil }
        let explicit = params.filter { $0.name.lowercased() == "type" }
        guard explicit.count <= 1 else { return nil }
        let transport: String
        switch scheme {
        case "vless", "trojan":
            switch explicit.first?.value?.lowercased() {
            case "tcp", "raw", "ws", "websocket", "grpc", "httpupgrade": transport = "tcp"
            case "kcp", "mkcp", "quic": transport = "udp"
            default: return nil
            }
        case "hysteria2", "hy2":
            transport = "udp"
        default:
            return nil
        }
        // The URL, user info, and query are discarded. Only the socket endpoint leaves this function.
        return Self(host: host, port: port, transport: transport)
    }
}

struct TransportEvidence: Codable {
    enum Kind: String, Codable {
        case tls, reality, quicTLS, vmessAEAD, shadowsocksAEAD, unencrypted, insecure, unknown

        var blocksActivation: Bool { ![.tls, .reality, .quicTLS, .vmessAEAD, .shadowsocksAEAD].contains(self) }


    }

    let endpointKey: String
    let kind: Kind

    static func inspect(_ text: String, endpoint: DetectedEndpoint) -> Self {
        let url = URLComponents(string: text.trimmingCharacters(in: .whitespacesAndNewlines))
        let options = url?.queryItems ?? []
        let insecureNames = ["insecure", "allowinsecure", "skipcertverify"]
        let disabledValues = ["0", "false", "no", "off"]
        let disablesVerification = options.contains { option in
            let name = option.name.lowercased().filter { $0 != "-" && $0 != "_" }
            return insecureNames.contains(name) && !disabledValues.contains(option.value?.lowercased() ?? "")
        }

        let kind: Kind
        if disablesVerification {
            kind = .insecure
        } else if ["hysteria2", "hy2"].contains(url?.scheme?.lowercased() ?? "") {
            let security = options.filter { $0.name.lowercased() == "security" }
            kind = security.isEmpty || (security.count == 1 && security[0].value?.lowercased() == "tls") ? .quicTLS : .unknown
        } else {
            let declared = options.filter { $0.name.lowercased() == "security" }
            switch declared.count == 1 ? declared.first?.value?.lowercased() : nil {
            case "tls": kind = .tls
            case "reality": kind = .reality
            case "none": kind = .unencrypted
            default: kind = .unknown
            }
        }
        return Self(endpointKey: endpoint.id, kind: kind)
    }
}
