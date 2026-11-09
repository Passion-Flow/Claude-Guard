import Darwin
import Foundation

struct DetectedEndpoint: Hashable, Identifiable, Sendable {
    let host: String
    let port: UInt16
    let transport: String

    var id: String { host + ":" + String(port) + "/" + transport }
    var label: String { host + ":" + String(port) + " · " + transport.uppercased() }

    private static let providerPath = "/Shadowrocket.app/Contents/PlugIns/MacPacketTunnel.appex/Contents/MacOS/MacPacketTunnel"
    private static let providerRequirement = """
    anchor apple generic and identifier "com.liguangming.Shadowrocket.PacketTunnel" and (
      certificate leaf[field.1.2.840.113635.100.6.1.9] exists or (
        certificate 1[field.1.2.840.113635.100.6.2.6] exists and
        certificate leaf[field.1.2.840.113635.100.6.1.13] exists and
        certificate leaf[subject.OU] = "JBJ55K5C9X"
      )
    )
    """

    static func observe(host: String) -> [Self] {
        guard GuardConfiguration.validIPv4(host) else { return [] }
        let uid = String(getuid())
        let processes = Tools.call("/bin/ps", ["-axo", "pid=,uid=,comm="])
        guard processes.code == 0 else { return [] }
        let providers = processes.text.split(whereSeparator: \.isNewline).compactMap { line -> String? in
            let columns = line.split(maxSplits: 2, whereSeparator: \.isWhitespace)
            guard columns.count == 3, Int(columns[0]) != nil, columns[1] == uid,
                  columns[2].hasSuffix(providerPath) else { return nil }
            let binary = String(columns[2])
            let verified = Tools.call("/usr/bin/codesign", ["--verify", "--strict", "-R=" + providerRequirement, binary])
            return verified.code == 0 ? String(columns[0]) : nil
        }
        guard !providers.isEmpty else { return [] }

        var found: Set<Self> = []
        for _ in 0..<3 {
            for pid in providers {
                let sockets = Tools.call("/usr/sbin/lsof", ["-n", "-P", "-a", "-p", pid, "-i4", "-F", "fPnT"])
                if sockets.code == 0 {
                    found.formUnion(parseSockets(sockets.text, host: host))
                }
            }
            Thread.sleep(forTimeInterval: 0.25)
        }
        return found.sorted { ($0.port, $0.transport) < ($1.port, $1.transport) }
    }

    static func parseSockets(_ listing: String, host: String) -> Set<Self> {
        var found: Set<Self> = []
        var protocolName = ""
        var remotePort: UInt16?
        var established = false
        let prefix = host + ":"

        func finishSocket() {
            guard let port = remotePort, port > 0,
                  protocolName == "UDP" || (protocolName == "TCP" && established) else { return }
            found.insert(Self(host: host, port: port, transport: protocolName.lowercased()))
        }

        for line in listing.split(whereSeparator: \.isNewline) {
            if line.hasPrefix("f") || line.hasPrefix("p") {
                finishSocket()
                protocolName = ""
                remotePort = nil
                established = false
            } else if line.hasPrefix("P") {
                protocolName = String(line.dropFirst())
            } else if line.hasPrefix("n"), let arrow = line.range(of: "->") {
                let remote = line[arrow.upperBound...]
                if remote.hasPrefix(prefix) { remotePort = UInt16(remote.dropFirst(prefix.count)) }
            } else if line == "TST=ESTABLISHED" {
                established = true
            }
        }
        finishSocket()
        return found
    }

    static func parseShareLink(_ input: String) -> Self? {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.utf8.count <= 8192,
              let url = URLComponents(string: value),
              let scheme = url.scheme?.lowercased(),
              let host = url.host, GuardConfiguration.validIPv4(host),
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
        case tls, reality, quicTLS, unencrypted, insecure, unknown

        var blocksActivation: Bool {
            switch self {
            case .tls, .reality, .quicTLS: return false
            case .unencrypted, .insecure, .unknown: return true
            }
        }

        var title: GuardText {
            switch self {
            case .tls: return GuardText("TLS declared")
            case .reality: return GuardText("REALITY declared")
            case .quicTLS: return GuardText("QUIC/TLS profile")
            case .unencrypted: return GuardText("Unencrypted profile")
            case .insecure: return GuardText("Certificate verification disabled")
            case .unknown: return GuardText("Not reviewed")
            }
        }
    }

    let endpointKey: String
    let kind: Kind

    static func inspect(_ text: String, endpoint: DetectedEndpoint) -> Self {
        let url = URLComponents(string: text.trimmingCharacters(in: .whitespacesAndNewlines))
        let options = url?.queryItems ?? []
        func matching(_ name: String) -> [URLQueryItem] {
            options.filter { $0.name.lowercased() == name }
        }
        let verificationAliases = ["insecure", "allowinsecure", "skipcertverify", "tlsinsecure"]
        let verification = options.filter {
            let normalized = $0.name.lowercased().filter { $0 != "-" && $0 != "_" }
            return verificationAliases.contains(normalized)
        }
        let explicit = matching("security")
        let scheme = url?.scheme?.lowercased()
        let kind: Kind
        if verification.count > 1 || verification.contains(where: {
            !["0", "false"].contains($0.value?.lowercased() ?? "")
        }) {
            kind = .insecure
        } else if explicit.count > 1 {
            kind = .unknown
        } else if ["hysteria2", "hy2"].contains(scheme ?? "") {
            kind = explicit.isEmpty || explicit.first?.value?.lowercased() == "tls" ? .quicTLS : .unknown
        } else {
            switch explicit.first?.value?.lowercased() {
            case "tls": kind = endpoint.transport == "tcp" ? .tls : .unknown
            case "reality":
                let publicKey = matching("pbk")
                let fingerprint = matching("fp")
                let key = publicKey.first?.value ?? ""
                let encoded = key.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
                let keyBytes = key.count == 43 ? Data(base64Encoded: encoded + "=") : nil
                let carrier = matching("type").first?.value?.lowercased() ?? ""
                kind = ["vless", "trojan"].contains(scheme ?? "") && ["tcp", "raw", "grpc"].contains(carrier) &&
                    publicKey.count == 1 && keyBytes?.count == 32 && fingerprint.count == 1 &&
                    !(fingerprint.first?.value ?? "").isEmpty ? .reality : .unknown
            case "none": kind = .unencrypted
            default: kind = .unknown
            }
        }
        return Self(endpointKey: endpoint.id, kind: kind)
    }
}
