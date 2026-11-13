import AppKit
import Foundation
import SwiftUI

@main
enum Launch {
    @MainActor static func main() {
        #if GUARD_DIAGNOSTICS
        if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--discovery-check" {
            do {
                let result = try AutomaticRoute.read(region: "US")
                let data = try JSONEncoder().encode(result.route)
                let url = URL(fileURLWithPath: CommandLine.arguments[2])
                try data.write(to: url, options: .atomic)
                guard chmod(url.path, 0o600) == 0 else { exit(1) }
                print("PASS: automatic profile, signed-provider socket, tunnel-bound DNS and exit discovery; endpoint redacted")
                return
            } catch {
                print("Automatic discovery is unconfirmed: \(error)")
                exit(1)
            }
        }
        if CommandLine.arguments.contains("--self-test") {
            exit(selfTest() ? 0 : 1)
        }
        #endif
        if CommandLine.arguments.count == 2 && CommandLine.arguments[1] == "--restore" {
            // Console recovery for an SSH session, where the authorization dialog cannot appear.
            guard geteuid() == 0 else {
                print("Run this command with sudo.")
                exit(77)
            }
            exit(GuardianClient.send(GuardianRequest(.restore), recovery: true).code)
        }
        #if GUARD_DIAGNOSTICS
        if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--preview" {
            do {
                try GuardPreviews.render(to: URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true))
                return
            } catch {
                print(error)
                exit(1)
            }
        }
        #endif
        if CommandLine.arguments.count == 2 && CommandLine.arguments[1] == "--recovery" {
            RecoveryApplication.main()
            return
        }
        guard CommandLine.arguments.count == 1 else { exit(64) }
        GuardApplication.main()
    }

    #if GUARD_DIAGNOSTICS
    @MainActor private static func selfTest() -> Bool {
        guard GuardController.automaticIssueLifecycleSelfTest() else { return false }
        guard AutomaticSetupIssue(ShadowrocketProfile.Failure.unavailable) == .profileAccess,
              AutomaticSetupIssue(ShadowrocketProfile.Failure.bootstrap) == .numericBootstrap,
              AutomaticSetupIssue(ShadowrocketProfile.Failure.routing) == .routingMode,
              AutomaticSetupIssue(AutomaticRoute.Failure.endpoint) == .providerEndpoint,
              AutomaticSetupIssue(AutomaticRoute.Failure.response) == .probeResponse,
              AutomaticSetupIssue(NSError(domain: "FixtureSecretMustNotAppear", code: 1)) == .unknown else { return false }
        guard GuardRiskPolicy.selfTest(), GuardRiskPolicy.keylessSelfTest(), BrowserRequest.selfTest(), BrowserDiagnostics.selfTest(), ServiceDiagnostics.selfTest(),
              GuardConfiguration.validIPv4("192.0.2.42"),
              !GuardConfiguration.validIPv4("192.0.2.256"),
              !GuardConfiguration.validIPv4("192.00.2.42"),
              !GuardConfiguration.validInterface("utun2; exit 0"),
              !GuardConfiguration.validInterface("utun2\n"),
              Snapshot("id|OPEN|100|utun2|192.0.2.42|192.0.2.42|probe-ok|0|live")?.phase == "OPEN",
              Snapshot("malformed") == nil else { return false }
        for protocolName in ["tcp", "udp"] {
            for phase in ["OPEN", "LOCKED", "SEALED"] {
                let rules = Tools.call("/bin/sh", ["-c", privilegedWorker, "claude-guard-worker",
                                                 "rules", "utun6", "192.0.2.42", protocolName, "443", phase])
                guard rules.code == 0, rules.text.contains("block drop quick all"),
                      rules.text.contains("keep state (if-bound) label \"CG_PEER_OUT\""),
                      !rules.text.contains("CG_PEER_IN"),
                      rules.text.contains("inet proto " + protocolName + " from any to 192.0.2.42 port = 443"),
                      (phase == "OPEN") == rules.text.contains("CG_TUNNEL"),
                      (phase == "LOCKED") == rules.text.contains("CG_PROBE_OUT") else { return false }
                if phase == "OPEN" {
                    guard rules.text.contains("pass quick on utun6 inet all no state label \"CG_TUNNEL\""),
                          !rules.text.contains("on utun6 all") else { return false }
                }
                if phase == "LOCKED" {
                    guard rules.text.contains("on utun6 inet proto tcp from any to 1.1.1.1 port = 443"),
                          rules.text.contains("on utun6 inet proto tcp from any to 1.0.0.1 port = 443") else { return false }
                }
                let checked = Tools.call("/sbin/pfctl", ["-n", "-a", "com.apple/00000.org.claudeguard.runtime", "-f", "-"],
                                         input: Data(rules.text.utf8))
                guard checked.code == 0 else { print(checked.text); return false }
            }
        }
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
        guard let endpoint = DetectedEndpoint.parseShareLink("vless://test@198.51.100.42:443?type=raw&security=reality"),
              TransportEvidence.inspect("vless://test@198.51.100.42:443?type=raw&security=reality", endpoint: endpoint).kind == .reality,
              TransportEvidence.inspect("vless://test@198.51.100.42:443?type=raw&security=none", endpoint: endpoint).kind.blocksActivation,
              TransportEvidence.inspect("vless://test@198.51.100.42:443?type=raw&security=tls&allowInsecure=1", endpoint: endpoint).kind.blocksActivation,
              TransportEvidence.inspect("vless://test@198.51.100.42:443?type=raw&security=tls&allow_insecure=1", endpoint: endpoint).kind.blocksActivation,
              TransportEvidence.inspect("vless://test@198.51.100.42:443?type=raw", endpoint: endpoint).kind.blocksActivation,
              TransportEvidence.inspect("vless://test@198.51.100.42:443?type=raw&security=none&security=none", endpoint: endpoint).kind.blocksActivation
        else { return false }
        let adminRules = Tools.call("/bin/sh", ["-c", privilegedWorker, "claude-guard-worker",
                                                "rules", "utun6", "192.0.2.42", "tcp", "443", "OPEN", "en0", "203.0.113.7"])
        guard adminRules.code == 0, adminRules.text.contains("label \"CG_ADMIN\""),
              Tools.call("/sbin/pfctl", ["-n", "-a", "com.apple/00000.org.claudeguard.runtime", "-f", "-"],
                         input: Data(adminRules.text.utf8)).code == 0 else { return false }
        let initial = TunnelCounters(name: "utun6", index: 2, uptime: 10, received: .max - 1, sent: 0)
        let after = TunnelCounters(name: "utun6", index: 2, uptime: 12, received: 2, sent: 100)
        guard after.rates(since: initial) == TunnelRates(received: 2, sent: 50),
              GuardText("Overview").en == "Overview", GuardText("Overview").zh != "Overview",
              GuardText("Trial · %1$@s", .plain("41")).en == "Trial · 41s",
              GuardText("Trial · %1$@s", .plain("41")).zh.contains("41") else { return false }
        let quote = "text with spaces ' quotes & pipes |"
        guard Tools.call("/bin/sh", ["-c", "printf %s " + Tools.shellQuote(quote)]).text == quote else { return false }
        let reportModel = GuardController(preview: true)
        reportModel.configuration.peer = "192.0.2.42"
        reportModel.riskKey = "FixtureSecretMustNotAppear"
        let report = reportModel.report(language: .english)
        guard report.contains("Risk admission"), !report.contains("192.0.2.42"),
              !report.contains("FixtureSecretMustNotAppear") else { return false }
        print("PASS: Endpoint detection, share links, status, shell quoting, traffic, localization and six PF rule variants")
        return true
    }
    #endif
}
