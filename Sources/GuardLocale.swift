import Foundation
import SwiftUI

struct GuardText: Equatable {
    enum Argument: Equatable {
        case plain(String)
        case localized(GuardText)

        func value(for language: GuardLanguage) -> String {
            switch self {
            case .plain(let string): return string
            case .localized(let text): return text[language]
            }
        }
    }

    private let key: String
    private let arguments: [Argument]

    init(_ key: String, _ arguments: Argument...) {
        self.key = key
        self.arguments = arguments
    }

    var zh: String { self[.chinese] }
    var en: String { self[.english] }

    subscript(language: GuardLanguage) -> String {
        let pattern = language.bundle?.localizedString(forKey: key, value: key, table: nil) ?? key
        guard !arguments.isEmpty else { return pattern }
        return String(format: pattern, locale: language.locale, arguments: arguments.map { $0.value(for: language) })
    }
}

enum GuardLanguage: String, CaseIterable {
    case chinese = "zh-Hans"
    case english = "en"

    var name: String { self == .chinese ? GuardText("Simplified Chinese")[.chinese] : "English" }

    private static let bundles: [Self: Bundle] = Dictionary(uniqueKeysWithValues: allCases.compactMap { language in
        guard let path = Bundle.main.path(forResource: language.rawValue, ofType: "lproj"),
              let bundle = Bundle(path: path) else { return nil }
        return (language, bundle)
    })
    var bundle: Bundle? { Self.bundles[self] }
    var locale: Locale { Locale(identifier: rawValue) }
    static var initial: Self { Locale.preferredLanguages.first?.hasPrefix("zh") == true ? .chinese : .english }
}

enum GuardAppearance: String, CaseIterable {
    case system, light, dark

    var scheme: ColorScheme? {
        switch self {
        case .system: return nil
        case .light: return .light
        case .dark: return .dark
        }
    }

    func title(_ language: GuardLanguage) -> String {
        switch self {
        case .system: return GuardText("System")[language]
        case .light: return GuardText("Light")[language]
        case .dark: return GuardText("Dark")[language]
        }
    }
}

enum GuardPolicy {
    static let id = "ipv4-tunnel-v1"
    static let version = "0.2.5"
    static let preferences = UserDefaults(suiteName: "org.claudeguard.appearance") ?? .standard
}

enum GuardCopy {
    static let reasons: [String: GuardText] = [
        "preflight": GuardText("Checking the system packet filter and the selected tunnel."),
        "probe-ok": GuardText("The approved exit was verified through the selected tunnel."),
        "stable-open": GuardText("Six checks passed over at least 15 seconds. Apps may use the tunnel."),
        "settling": GuardText("The VPN is connected. App traffic stays blocked while the tunnel and approved exit are being verified."),
        "route-changed": GuardText("A visible network route changed. Apps remain blocked while validation restarts."),
        "underlay-offline": GuardText("The local network is unavailable. App traffic stays blocked while Wi-Fi or Ethernet recovers."),
        "vpn-restarting": GuardText("The local network returned, but the tunnel did not recover. Restarting the original VPN service once."),
        "route-unknown": GuardText("System routes could not be read. App traffic remains blocked."),
        "probe-backup": GuardText("The backup probe verified the approved exit."),
        "probe-retry": GuardText("A probe timed out. The original tunnel is still connected and direct traffic remains blocked while the check retries."),
        "probe-failed": GuardText("Exit checks failed. App traffic remains blocked."),
        "exit-mismatch": GuardText("The observed exit differs from the approved exit. App traffic remains blocked."),
        "pf-layout": GuardText("This beta cannot validate the current packet-filter layout. Protection was not enabled."),
        "tunnel-unverified": GuardText("The selected tunnel could not be matched to the Shadowrocket service. Run detection again."),
        "revalidating": GuardText("The original Shadowrocket service has a tunnel. Exit validation is restarting."),
        "vpn-wait": GuardText("Waiting for the original Shadowrocket service. App traffic remains blocked."),
        "vpn-reconnect": GuardText("macOS was asked to reconnect the original Shadowrocket service. Waiting for validation."),
        "trial-paused": GuardText("The trial expired and traffic remains blocked. Continue protection or explicitly restore networking on this Mac."),
        "worker-stopped": GuardText("The guardian stopped unexpectedly and did not release its rules. Use the local recovery tool."),
        "tunnel-missing": GuardText("The tunnel disappeared. Restore networking and run detection again."),
        "pf-load": GuardText("macOS could not load or verify the protection rules."),
        "pf-changed": GuardText("The system packet filter changed. Protection coverage cannot be confirmed."),
        "rollback-failed": GuardText("Recovery did not complete. Try Restore network again or restart this Mac to clear the session rules."),
        "trial-ended": GuardText("The trial ended and the original rules were restored."),
        "stopped": GuardText("The Claude Guard rules were removed."),
    ]

    static func reason(_ code: String) -> GuardText {
        reasons[code] ?? GuardText("Status updated.")
    }

    private static let eventTitles: [String: GuardText] = [
        "detect": GuardText("Detection"),
        "start-aborted": GuardText("Activation canceled"),
        "restore-error": GuardText("Recovery issue"),
        "startup-error": GuardText("Activation issue"),
        "ended": GuardText("Stopped"),
    ]

    static func eventCode(_ code: String) -> String {
        if eventTitles[code] != nil { return code }
        // Earlier versions stored the translated title as the event identifier.
        return eventTitles.first(where: { $0.value.zh == code })?.key ?? code
    }

    static func phase(_ code: String) -> GuardText {
        if let title = eventTitles[eventCode(code)] { return title }
        switch code {
        case "IDLE": return GuardText("Inactive")
        case "VERIFYING": return GuardText("Checking")
        case "LOCKED": return GuardText("Traffic blocked")
        case "OPEN": return GuardText("Protection active")
        case "DRIFT": return GuardText("System rules changed")
        case "ERROR": return GuardText("Protection check failed")
        default: return GuardText("Event")
        }
    }

    static func date(_ value: Date, _ language: GuardLanguage) -> String {
        value.formatted(Date.FormatStyle(date: .abbreviated, time: .standard, locale: language.locale))
    }
}

struct GuardPalette {
    let dark: Bool

    var canvas: Color { shade(0xf7f3ec, 0x23201d) }
    var sidebar: Color { shade(0xeee8de, 0x1d1a18) }
    var surface: Color { shade(0xfffcf7, 0x2e2925) }
    var ink: Color { shade(0x2a2520, 0xf4ede4) }
    var secondary: Color { shade(0x665d54, 0xc0b2a5) }
    var line: Color { shade(0xddd2c3, 0x51473e) }
    var accent: Color { shade(0xa04731, 0xef9b7c) }
    var highlight: Color { shade(0xf0e0d6, 0x463229) }
    var good: Color { shade(0x316148, 0x96cea9) }
    var caution: Color { shade(0x8b5528, 0xf0b579) }
    var bad: Color { shade(0x963d34, 0xe9a098) }

    private func shade(_ light: Int, _ dark: Int) -> Color {
        let v = self.dark ? dark : light
        return Color(red: Double((v >> 16) & 255) / 255, green: Double((v >> 8) & 255) / 255, blue: Double(v & 255) / 255)
    }
}
