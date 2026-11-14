import Foundation

@main enum LeaseFixture {
    static func main() {
        let session = "00000000-0000-4000-8000-000000000001"
        let service = "00000000-0000-4000-8000-000000000002"
        let endpoint = "192.0.2.42:443/tcp"
        let expected = "198.51.100.42"
        let original = ["1", session, "OPEN", "100", "99", "90", "utun6", service, endpoint, expected, "1"]
        func call(_ lease: inout GuardianObservationLease, _ fields: [String] = original,
                  wall: Double = 100, uptime: Double = 50, suffix: String = "\n") -> Bool {
            lease.accepts(fields.joined(separator: "|") + suffix, session: session, service: service,
                interface: "utun6", endpoint: endpoint, expected: expected, wall: wall, uptime: uptime)
        }
        func fresh(_ fields: [String] = original, wall: Double = 100, uptime: Double = 50,
                   suffix: String = "\n") -> Bool {
            var lease = GuardianObservationLease()
            return call(&lease, fields, wall: wall, uptime: uptime, suffix: suffix)
        }
        precondition(fresh() && fresh(suffix: ""))
        var prepared = original; prepared[2] = "ADMITTING"
        precondition(fresh(prepared) && !fresh(prepared, wall: 111))
        func restrictive(_ fields: [String], wall: Double = 100) -> Bool {
            GuardianObservationLease.restrictivePublication(fields.joined(separator: "|") + "\n",
                session: session, service: service, endpoint: endpoint, expected: expected, wall: wall)
        }
        precondition(!restrictive(original))
        var locked = original; locked[2] = "LOCKED"
        precondition(restrictive(locked) && !fresh(locked))
        precondition(!restrictive(locked, wall: 112) && !restrictive(locked, wall: 99))
        for (index, value) in [(0, "2"), (1, service), (2, "IDLE"), (3, "0100"),
            (3, "100.0"), (3, "nan"), (7, session), (8, "other"), (9, "other")] {
            var invalid = locked; invalid[index] = value
            precondition(!restrictive(invalid))
        }
        for (index, value) in [(0, "2"), (1, service), (2, "LOCKED"), (3, "98"), (3, "101"),
            (4, "0"), (4, "-1"), (4, "099"), (4, "99.0"), (4, "1e2"), (4, "nan"),
            (4, "1000000000000"), (5, "101"), (6, "utun7"), (7, session), (8, "other"),
            (9, "192.0.2.1"), (10, "0")] {
            var bad = original; bad[index] = value
            precondition(!fresh(bad), "Accepted invalid field \(index)")
        }
        precondition(!fresh(suffix: "\n\n") && !fresh(suffix: "\r\n"))
        precondition(!fresh(Array(original.dropLast())) && !fresh(original + ["extra"]))
        precondition(!fresh(wall: .nan) && !fresh(uptime: .infinity) && !fresh(uptime: -1))
        precondition(fresh(wall: 110.999) && !fresh(wall: 111))

        var lease = GuardianObservationLease()
        precondition(call(&lease))
        var heartbeat = original; heartbeat[3] = "110"
        precondition(call(&lease, heartbeat, wall: 110, uptime: 60))
        heartbeat[3] = "111"
        precondition(!call(&lease, heartbeat, wall: 111, uptime: 61))

        lease = GuardianObservationLease(); precondition(call(&lease))
        precondition(!call(&lease, wall: 100.5, uptime: 62), "Wall rewind renewed old observation")
        lease = GuardianObservationLease(); precondition(call(&lease))
        var newer = original; newer[3] = "105"; newer[4] = "104"
        precondition(call(&lease, newer, wall: 105, uptime: 55))
        var older = newer; older[4] = "103"
        precondition(!call(&lease, older, wall: 105, uptime: 55))
        newer[5] = "89"
        precondition(!call(&lease, newer, wall: 105, uptime: 55))

        lease = GuardianObservationLease(); precondition(call(&lease))
        newer = original; newer[3] = "101"; newer[4] = "101"
        precondition(!call(&lease, newer, wall: 101, uptime: 3641), "New identity extended original risk lifetime")
        newer[5] = "101"
        precondition(call(&lease, newer, wall: 101, uptime: 3641))
        var expiredRisk = original; expiredRisk[3] = "3690"; expiredRisk[4] = "3690"
        precondition(!fresh(expiredRisk, wall: 3690))
        print("PASS: strict proof schema, context, publication/observation separation, expiry, monotonic clocks and risk lifetime")
    }
}
