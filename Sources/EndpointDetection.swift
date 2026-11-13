import Darwin
import Foundation

extension DetectedEndpoint {
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

}

extension TransportEvidence.Kind {
    var title: GuardText {
        switch self {
        case .tls: return GuardText("TLS declared")
        case .reality: return GuardText("REALITY declared")
        case .quicTLS: return GuardText("QUIC/TLS profile")
        case .vmessAEAD: return GuardText("VMess AEAD profile")
        case .shadowsocksAEAD: return GuardText("Shadowsocks AEAD profile")
        case .unencrypted: return GuardText("Unencrypted profile")
        case .insecure: return GuardText("Certificate verification disabled")
        case .unknown: return GuardText("Not reviewed")
        }
    }
}
