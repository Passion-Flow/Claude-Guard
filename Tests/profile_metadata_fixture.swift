import Foundation

@objc(CGFixtureServer)
final class FixtureServer: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }
    let values: [String: Any]
    init(_ values: [String: Any]) { self.values = values }
    required init?(coder: NSCoder) { return nil }
    func encode(with coder: NSCoder) { for (key, value) in values { coder.encode(value, forKey: key) } }
}

@main
enum ProfileFixture {
    static func main() throws {
        let selection = "opaque-selection-identifier"
        let settings = try PropertyListSerialization.data(fromPropertyList: ["group.com.liguangming.SelectedServerUUID": selection, "group.com.liguangming.GlobalRoutingMethod": "Proxy"], format: .binary, options: 0)
        let baseline: [String: Any] = ["uuid": selection, "host": "198.51.100.42", "port": "443", "type": "Vmess", "proto": "none", "tls": false, "allowInsecure": false, "method": "chacha20-poly1305", "alterId": "0", "password": "FixtureMustNeverBeDecoded"]
        func archive(_ rows: [[String: Any]]) -> Data {
            let archiver = NSKeyedArchiver(requiringSecureCoding: true)
            archiver.setClassName("DLWServer", for: FixtureServer.self)
            archiver.encode(rows.map(FixtureServer.init), forKey: NSKeyedArchiveRootObjectKey)
            archiver.finishEncoding()
            return archiver.encodedData
        }
        func reject(_ rows: [[String: Any]]) -> Bool { (try? ShadowrocketProfile.decode(archive: archive(rows), preferences: settings)) == nil }
        for mode in ["Config", "Direct", "", "proxy"] {
            let settings = try PropertyListSerialization.data(fromPropertyList: ["group.com.liguangming.SelectedServerUUID": selection, "group.com.liguangming.GlobalRoutingMethod": mode], format: .binary, options: 0)
            precondition((try? ShadowrocketProfile.decode(archive: archive([baseline]), preferences: settings)) == nil)
        }
        let valid = try ShadowrocketProfile.decode(archive: archive([baseline]), preferences: settings)
        precondition(valid.security == .vmessAEAD && valid.transport == "tcp" && valid.fingerprint.count == 64)
        precondition(reject([]) && reject([baseline, baseline]))
        for (key, value) in [("tls", "unknown"), ("allowInsecure", true), ("port", "00443"), ("port", "0"), ("host", "host\n.invalid"), ("host", "node.example.invalid"), ("proto", "unknown"), ("method", "none"), ("alterId", "64")] as [(String, Any)] {
            var row = baseline; row[key] = value; precondition(reject([row]), key)
        }
        precondition((try? ShadowrocketProfile.decode(archive: Data("bad".utf8), preferences: settings)) == nil)
        precondition(GuardRiskPolicy.selfTest() && GuardRiskPolicy.keylessSelfTest())
        print("PASS: metadata whitelist, opaque selection, duplicate/malformed profile rejection, encryption policy and typed keyless risk admission")
    }
}
