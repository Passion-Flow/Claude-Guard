import CryptoKit
import Foundation

struct ShadowrocketProfile: Equatable, Sendable {
    let selection: String
    let host: String
    let port: UInt16
    let transport: String
    let security: TransportEvidence.Kind

    var fingerprint: String {
        let value = [selection, host, String(port), transport, security.rawValue].joined(separator: "|")
        return SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    static func readCurrent(base approvedDirectory: URL? = nil) throws -> Self {
        let base = approvedDirectory ?? FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Group Containers/group.com.liguangming.Shadowrocket")
        let preferences = try bounded(base.appendingPathComponent("Library/Preferences/group.com.liguangming.Shadowrocket.plist"), maximum: 65536)
        let archive = try bounded(base.appendingPathComponent("ServerManager"), maximum: 4194304)
        let result = try decode(archive: archive, preferences: preferences)
        let after = try bounded(base.appendingPathComponent("Library/Preferences/group.com.liguangming.Shadowrocket.plist"), maximum: 65536)
        guard preferences == after else { throw Failure.changed }
        return result
    }

    enum Failure: Error { case unavailable, invalid, ambiguous, unsupported, changed, routing, bootstrap }

    private static func bounded(_ url: URL, maximum: Int) throws -> Data {
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Failure.unavailable }
        defer { close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0, metadata.st_uid == getuid(),
              metadata.st_mode & S_IFMT == S_IFREG, (1...maximum).contains(Int(metadata.st_size)) else { throw Failure.invalid }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        guard let data = try handle.read(upToCount: maximum + 1), data.count <= maximum else { throw Failure.invalid }
        return data
    }

    static func decode(archive: Data, preferences: Data) throws -> Self {
        guard archive.count <= 4194304, preferences.count <= 65536,
              let settings = try PropertyListSerialization.propertyList(from: preferences, format: nil) as? [String: Any],
              let selection = settings["group.com.liguangming.SelectedServerUUID"] as? String,
              !selection.isEmpty, selection.utf8.count <= 256 else { throw Failure.invalid }
        guard settings["group.com.liguangming.GlobalRoutingMethod"] as? String == "Proxy" else { throw Failure.routing }
        let decoder = try NSKeyedUnarchiver(forReadingFrom: archive)
        decoder.decodingFailurePolicy = .setErrorAndReturn
        decoder.requiresSecureCoding = true
        decoder.setClass(ShadowrocketProfileRecord.self, forClassName: "DLWServer")
        guard let decoded = decoder.decodeObject(of: [NSArray.self, ShadowrocketProfileRecord.self], forKey: NSKeyedArchiveRootObjectKey) as? [ShadowrocketProfileRecord],
              decoded.count <= 10000, decoder.error == nil else { throw Failure.invalid }
        decoder.finishDecoding()
        guard decoder.error == nil else { throw Failure.invalid }
        let records = decoded.map(\.fields).filter { $0["uuid"] as? String == selection }
        guard records.count == 1 else { throw records.isEmpty ? Failure.unavailable : Failure.ambiguous }
        let record = records[0]
        func resolve(_ value: Any?) -> Any? { value }
        func text(_ name: String) -> String? { resolve(record[name]) as? String }
        func flag(_ name: String) -> Bool? {
            if let value = resolve(record[name]) as? NSNumber {
                guard ["c", "i", "q", "B"].contains(String(cString: value.objCType)), [0, 1].contains(value.intValue) else { return nil }
                return value.intValue == 1
            }
            if let value = text(name), ["0", "1"].contains(value) { return value == "1" }
            return nil
        }
        guard let rawHost = text("host"), let type = text("type")?.lowercased(),
              let rawPort = text("port"), let port = UInt16(rawPort), port > 0, String(port) == rawPort,
              let tls = flag("tls"), let insecure = flag("allowInsecure"), !insecure else { throw Failure.unsupported }
        let host = rawHost.lowercased()
        // Reconnection must not depend on DNS outside the approved VPN path.
        // Resolving a hostname while connected cannot prove cold bootstrap.
        guard DetectedEndpoint.validIPv4(host) else { throw Failure.bootstrap }
        let proto = text("proto")?.lowercased() ?? "none"
        guard ["none", "tcp", "raw", "ws", "websocket", "grpc", "httpupgrade"].contains(proto) else { throw Failure.unsupported }
        let security: TransportEvidence.Kind
        switch type {
        case "vless":
            if let key = text("publicKey"), !key.isEmpty {
                let base64 = key.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
                let padded = base64 + String(repeating: "=", count: (4 - base64.count % 4) % 4)
                guard key.range(of: #"^[A-Za-z0-9_-]{43}\z"#, options: .regularExpression) != nil,
                      Data(base64Encoded: padded)?.count == 32, let peer = text("peer"),
                      peer.utf8.count <= 253, peer.range(of: #"^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]\z"#, options: .regularExpression) != nil else { throw Failure.unsupported }
                security = .reality
            }
            else if tls { security = .tls }
            else { throw Failure.unsupported }
        case "trojan":
            guard tls else { throw Failure.unsupported }
            security = .tls
        case "vmess":
            if tls { security = .tls }
            else {
                guard text("alterId") == "0", ["chacha20-poly1305", "aes-128-gcm"].contains(text("method") ?? "") else { throw Failure.unsupported }
                security = .vmessAEAD
            }
        case "shadowsocks", "ss":
            guard ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"].contains(text("method") ?? ""),
                  [nil, "none"].contains(text("obfs")) else { throw Failure.unsupported }
            security = .shadowsocksAEAD
        default: throw Failure.unsupported
        }
        return Self(selection: selection, host: host, port: port, transport: "tcp", security: security)
    }
}

// Only the connection/security metadata is decoded. Passwords, encryption keys,
// subscription data and the raw node payload have no decoding entry point.
@objc(CGShadowrocketMetadataRecord)
private final class ShadowrocketProfileRecord: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }
    let fields: [String: Any]

    required init?(coder: NSCoder) {
        var values: [String: Any] = [:]
        for name in ["uuid", "host", "port", "type", "proto", "tls", "allowInsecure", "method", "alterId", "publicKey", "peer", "obfs"] {
            if coder.containsValue(forKey: name), let value = coder.decodeObject(of: [NSString.self, NSNumber.self], forKey: name) {
                values[name] = value
            }
        }
        guard coder.error == nil else { return nil }
        fields = values
        super.init()
    }

    func encode(with coder: NSCoder) {
        for (key, value) in fields { coder.encode(value, forKey: key) }
    }
}
