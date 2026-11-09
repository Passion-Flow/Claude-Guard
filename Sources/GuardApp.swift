import AppKit
import Foundation
import SwiftUI

@main
enum Launch {
    @MainActor static func main() {
        #if GUARD_DIAGNOSTICS
        if CommandLine.arguments.contains("--self-test") {
            exit(selfTest() ? 0 : 1)
        }
        if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--preview" {
            do {
                try GuardPreviews.render(to: URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true))
                return
            } catch {
                print(error)
                exit(1)
            }
        }
        #else
        if !Set(CommandLine.arguments).isDisjoint(with: ["--self-test", "--preview"]) { exit(64) }
        #endif
        if Bundle.main.bundleIdentifier == "org.claudeguard.recovery" {
            RecoveryApplication.main()
        } else {
            GuardApplication.main()
        }
    }

    #if GUARD_DIAGNOSTICS
    private static func selfTest() -> Bool {
        guard GuardConfiguration.validIPv4("192.0.2.42"),
              !GuardConfiguration.validIPv4("192.0.2.256"),
              !GuardConfiguration.validIPv4("192.00.2.42"),
              !GuardConfiguration.validInterface("utun2; exit 0"),
              Snapshot("id|OPEN|100|utun2|192.0.2.42|192.0.2.42|probe-ok|0|live")?.phase == "OPEN",
              Snapshot("malformed") == nil else { return false }
        for protocolName in ["tcp", "udp"] {
            for phase in ["OPEN", "LOCKED", "SEALED"] {
                let rules = Tools.call("/bin/sh", ["-c", privilegedWorker, "claude-guard-worker",
                                                 "rules", "utun6", "192.0.2.42", protocolName, "443", phase])
                guard rules.code == 0, rules.text.contains("block drop quick all"),
                      rules.text.contains("keep state (if-bound) label \"CG_PEER_OUT\""),
                      !rules.text.contains("CG_PEER_IN"),
                      rules.text.contains("pass out quick on en0 inet proto " + protocolName + " from any to 192.0.2.42 port = 443"),
                      (phase == "OPEN") == rules.text.contains("CG_TUNNEL"),
                      (phase == "LOCKED") == rules.text.contains("CG_PROBE_OUT") else { return false }
                if phase == "OPEN" {
                    guard rules.text.contains("pass quick on utun6 inet all no state label \"CG_TUNNEL\""),
                          !rules.text.contains("on utun6 all") else { return false }
                }
                if phase == "LOCKED" {
                    guard rules.text.contains("on utun6 inet proto tcp from any to 1.1.1.1 port = 443 user root"),
                          rules.text.contains("on utun6 inet proto tcp from any to 1.0.0.1 port = 443 user root") else { return false }
                }
                let checked = Tools.call("/sbin/pfctl", ["-n", "-a", "com.apple/00000.org.claudeguard.runtime", "-f", "-"],
                                         input: Data(rules.text.utf8))
                guard checked.code == 0 else { print(checked.text); return false }
            }
        }
        let multiline = Tools.call("/bin/sh", ["-c", privilegedWorker, "claude-guard-worker",
                                               "rules", "utun6", "192.0.2.42\n192.0.2.43", "tcp", "443", "SEALED"])
        let malformedInterface = Tools.call("/bin/sh", ["-c", privilegedWorker, "claude-guard-worker",
                                                        "rules", "utun6\nX", "192.0.2.42", "tcp", "443", "SEALED"])
        guard multiline.code == 2, malformedInterface.code == 2 else { return false }
        let fixture = """
        p123
        f20
        PTCP
        n192.0.2.9:51000->198.51.100.42:443
        TST=ESTABLISHED
        f21
        PTCP
        n192.0.2.9:51000->198.51.100.42:8443
        TST=CLOSED
        f22
        PUDP
        n192.0.2.9:51001->198.51.100.42:10443
        f23
        PUDP
        n198.51.100.42:9999->192.0.2.9:51413
        """
        let observed = DetectedEndpoint.parseSockets(fixture, host: "198.51.100.42")
        guard observed.map(\.id).sorted() == ["198.51.100.42:10443/udp", "198.51.100.42:443/tcp"],
              DetectedEndpoint.parseShareLink("vless://test@198.51.100.42:443?type=raw&security=reality")?.transport == "tcp",
              DetectedEndpoint.parseShareLink("hysteria2://test@198.51.100.42:10443")?.transport == "udp",
              DetectedEndpoint.parseShareLink("hysteria2://test@198.51.100.42:10443?mport=10443-10447") == nil,
              DetectedEndpoint.parseShareLink("https://example.invalid/sub") == nil else { return false }
        let baseLink = "vless://test@198.51.100.42:443?type=raw"
        let reality = baseLink + "&security=reality&fp=chrome&pbk=" + String(repeating: "A", count: 43)
        let tls = baseLink + "&security=tls&allowInsecure=0&encryption=none"
        let quic = "hysteria2://test@198.51.100.42:10443?insecure=0"
        guard let endpoint = DetectedEndpoint.parseShareLink(reality),
              let udp = DetectedEndpoint.parseShareLink(quic),
              TransportEvidence.inspect(reality, endpoint: endpoint).kind == .reality,
              TransportEvidence.inspect(tls, endpoint: endpoint).kind == .tls,
              TransportEvidence.inspect(quic, endpoint: udp).kind == .quicTLS
        else { return false }
        let rejected = [
            baseLink,
            baseLink + "&security=none",
            baseLink + "&security=tls&security=none",
            baseLink + "&security=none&security=none",
            baseLink + "&security=reality",
            tls + "&skip_cert_verify=false",
            baseLink + "&security=tls&allowInsecure=1",
            baseLink + "&security=tls&allowInsecure",
            baseLink + "&security=tls&%69nsecure=yes",
        ]
        let unsupportedTLS = "vless://test@198.51.100.42:443?type=kcp&security=tls"
        guard let unsupported = DetectedEndpoint.parseShareLink(unsupportedTLS),
              TransportEvidence.inspect(unsupportedTLS, endpoint: unsupported).kind.blocksActivation,
              rejected.allSatisfy({ TransportEvidence.inspect($0, endpoint: endpoint).kind.blocksActivation }),
              TransportEvidence.inspect(quic + "&security=none", endpoint: udp).kind.blocksActivation else { return false }
        let initial = TunnelCounters(name: "utun6", index: 2, uptime: 10, received: .max - 1, sent: 0)
        let after = TunnelCounters(name: "utun6", index: 2, uptime: 12, received: 2, sent: 100)
        guard after.rates(since: initial) == TunnelRates(received: 2, sent: 50),
              GuardText("Overview").en == "Overview", GuardText("Overview").zh != "Overview",
              GuardText("Trial · %1$@s", .plain("41")).en == "Trial · 41s",
              GuardText("Trial · %1$@s", .plain("41")).zh.contains("41") else { return false }
        let quote = "text with spaces ' quotes & pipes |"
        guard Tools.call("/bin/sh", ["-c", "printf %s " + Tools.shellQuote(quote)]).text == quote else { return false }
        print("PASS: Endpoint detection, share links, status, shell quoting, traffic, localization and six PF rule variants")
        return true
    }
    #endif
}
