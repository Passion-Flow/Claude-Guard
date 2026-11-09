import Darwin
import Foundation

struct TunnelRates: Equatable {
    let received: Double
    let sent: Double

    static func format(_ value: Double?, language: GuardLanguage) -> String {
        guard let value else { return "—" }
        if value >= 1_000_000 {
            return String(format: "%.1f MB/s", locale: language.locale, value / 1_000_000)
        }
        if value >= 1_000 {
            return String(format: "%.1f KB/s", locale: language.locale, value / 1_000)
        }
        return String(format: "%.0f B/s", locale: language.locale, value)
    }
}

struct TunnelCounters {
    let name: String
    let index: UInt32
    let uptime: TimeInterval
    let received: UInt32
    let sent: UInt32

    static func read(interface: String) -> Self? {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0, let first else { return nil }
        defer { freeifaddrs(first) }
        var next: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = next {
            next = entry.pointee.ifa_next
            let row = entry.pointee
            guard let name = row.ifa_name, String(cString: name) == interface,
                  row.ifa_addr?.pointee.sa_family == UInt8(AF_LINK),
                  let stats = row.ifa_data?.assumingMemoryBound(to: if_data.self).pointee else { continue }
            return Self(name: interface, index: if_nametoindex(name),
                        uptime: ProcessInfo.processInfo.systemUptime, received: stats.ifi_ibytes, sent: stats.ifi_obytes)
        }
        return nil
    }

    func rates(since previous: Self) -> TunnelRates? {
        let elapsed = uptime - previous.uptime
        guard name == previous.name, index == previous.index, elapsed > 0, elapsed < 12 else { return nil }
        let rx = received &- previous.received
        let tx = sent &- previous.sent
        // A wrap is valid. A large discontinuity is more likely a reset or a recycled tunnel.
        guard rx < UInt32.max / 2, tx < UInt32.max / 2 else { return nil }
        return TunnelRates(received: Double(rx) / elapsed, sent: Double(tx) / elapsed)
    }
}
