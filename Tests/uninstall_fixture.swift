import Foundation

private final class Host {
    var jobs = Set(["system/org.claudeguard.daemon", "system/org.claudeguard.offline-recovery", "gui/501/org.claudeguard.mac"])
    var receipts = Set(GuardianUninstall.receipts)
    var calls: [(String, [String])] = []
    var rules = true
    var stopped = false
    var stickyJob = false
    var queryError = false
    var flushError = false
    var receiptError = false
    var missingAnchor = false
    var parentHasAnchor = false
    var busy = 0
    var reads = 0
    var lateWriter = false
    var printError = false
    var released = Set<String>()

    func run(_ path: String, _ args: [String], _ timeout: TimeInterval) -> GuardianUninstall.Result {
        calls.append((path, args))
        precondition(timeout > 0 && timeout <= 8)
        if path == "/bin/launchctl" {
            if args.first == "asuser" { return .init(code: 0) }
            if args.first == "print" {
                if printError { return .init(code: 1, error: "Permission denied") }
                return .init(code: jobs.contains(args[1]) ? 0 : 113)
            }
            if args.first == "bootout" {
                if !stickyJob { jobs.remove(args[1]) }
                return .init(code: stickyJob ? 1 : 0)
            }
        }
        if path == "/sbin/pfctl" {
            precondition(stopped, "Stop every Guard writer before touching PF")
            if args == ["-a", GuardianUninstall.anchor, "-sr"] {
                reads += 1
                if busy > 0 { busy -= 1; return .init(code: 0, output: "partial", error: "Resource busy") }
                if queryError || missingAnchor { return .init(code: 1) }
                return .init(code: 0, output: rules || (lateWriter && reads >= 3) ? "block drop quick all\n" : "")
            }
            if args == ["-a", "com.apple", "-s", "Anchors"] {
                return .init(code: queryError ? 1 : 0, output: parentHasAnchor ? "00000.org.claudeguard.runtime/child\n" : "unrelated\n")
            }
            if args == ["-a", GuardianUninstall.anchor, "-F", "rules"] {
                if !flushError { rules = false }
                return .init(code: flushError ? 1 : 0)
            }
            if args.first == "-X" { released.insert(args[1]); return .init(code: 0) }
            fatalError("Unscoped or unexpected PF operation: \(args)")
        }
        if path == "/usr/sbin/pkgutil" {
            precondition(GuardianUninstall.receipts.contains(args[1]), "Never alter another package receipt")
            if args.first == "--pkg-info" { return .init(code: receipts.contains(args[1]) ? 0 : 1) }
            if args.first == "--forget" {
                if !receiptError { receipts.remove(args[1]) }
                return .init(code: receiptError ? 1 : 0)
            }
        }
        fatalError("Unexpected command: \(path) \(args)")
    }
}

@main
enum UninstallFixture {
    static func main() throws {
        setbuf(stdout, nil)
        let base = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("cg-native-uninstall-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: base) }
        var passed = 0

        func scenario(_ name: String, failure: Bool = false, setup: (URL, Host) throws -> Void = { _, _ in }) throws {
            let root = base.appendingPathComponent(name)
            let host = Host()
            func put(_ path: String, _ value: String = "fixture") throws {
                let url = root.appendingPathComponent(String(path.dropFirst()))
                try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
                try Data(value.utf8).write(to: url)
            }
            for label in GuardianUninstall.systemLabels { try put("/Library/LaunchDaemons/" + label + ".plist") }
            try put("/Library/LaunchAgents/org.claudeguard.mac.plist")
            try put("/Applications/Claude Guard.app/Contents/MacOS/ClaudeGuard")
            try put(GuardianUninstall.helperDirectory + "/state/filter.json", "{\"pfToken\":\"1234\"}")
            try put("/private/var/run/org.claudeguard.runtime/active/token", "5678\n")
            try put(GuardianUninstall.recoveryDirectory + "/Uninstall.pkg")
            try put("/Users/test/Library/Preferences/org.claudeguard.mac.plist")
            try put("/Users/test/Library/Caches/org.claudeguard.mac/data")
            try put("/Users/test/Library/Application Support/Claude Guard/events")
            try put("/Applications/Unrelated.app/Contents/keep")
            try put("/Library/LaunchDaemons/com.example.unrelated.plist")
            try put("/Users/test/Documents/Exported-Guard-Report.txt")
            try setup(root, host)
            guard let canonical = realpath(root.path, nil) else { fatalError("Fixture path missing") }
            let rootPath = String(cString: canonical)
            free(canonical)
            let uninstall = GuardianUninstall(testRoot: rootPath, users: [.init(uid: 501, home: "/Users/test")],
                command: host.run, stopProcesses: {
                    precondition(host.jobs.isEmpty)
                    host.stopped = true
                })
            do {
                try uninstall.perform()
                precondition(!failure, "Expected failure: " + name)
                precondition(host.jobs.isEmpty && host.receipts.isEmpty)
                for path in ["Applications/Claude Guard.app", "Library/PrivilegedHelperTools/org.claudeguard",
                             "Library/LaunchAgents/org.claudeguard.mac.plist", "private/var/run/org.claudeguard.runtime",
                             "Users/Shared/Claude Guard Recovery", "Users/test/Library/Preferences/org.claudeguard.mac.plist",
                             "Users/test/Library/Caches/org.claudeguard.mac", "Users/test/Library/Application Support/Claude Guard"] {
                    precondition(!FileManager.default.fileExists(atPath: root.appendingPathComponent(path).path), "Residual " + path)
                }
                try uninstall.perform() // Repeated removal is successful and does not recreate anything.
            } catch {
                precondition(failure, "Unexpected failure in " + name + ": \(error)")
            }
            for path in ["Applications/Unrelated.app/Contents/keep", "Library/LaunchDaemons/com.example.unrelated.plist",
                         "Users/test/Documents/Exported-Guard-Report.txt"] {
                precondition(FileManager.default.fileExists(atPath: root.appendingPathComponent(path).path))
            }
            if name == "complete" { precondition(host.released == ["1234", "5678"]) }
            if name == "job-remains" || name == "job-read-error" { precondition(!host.calls.contains { $0.0 == "/sbin/pfctl" }) }
            passed += 1
            print("PASS: " + name)
        }
        try scenario("complete")
        try scenario("app-already-removed") { root, _ in
            try FileManager.default.removeItem(at: root.appendingPathComponent("Applications/Claude Guard.app"))
        }
        try scenario("helper-and-trust-already-removed") { root, _ in
            try FileManager.default.removeItem(at: root.appendingPathComponent("Library/PrivilegedHelperTools/org.claudeguard"))
        }
        try scenario("app-and-helper-missing") { root, _ in
            for path in ["Applications/Claude Guard.app", "Library/PrivilegedHelperTools/org.claudeguard"] {
                try FileManager.default.removeItem(at: root.appendingPathComponent(path))
            }
        }
        try scenario("job-remains", failure: true) { _, host in host.stickyJob = true }
        try scenario("job-read-error", failure: true) { _, host in host.printError = true }
        try scenario("pf-read-error", failure: true) { _, host in host.queryError = true }
        try scenario("pf-flush-error", failure: true) { _, host in host.flushError = true }
        try scenario("pf-busy-retry") { _, host in host.busy = 2 }
        try scenario("pf-busy-persists", failure: true) { _, host in host.busy = 3 }
        try scenario("anchor-absent-confirmed") { _, host in host.missingAnchor = true }
        try scenario("child-anchor-not-absent", failure: true) { _, host in host.missingAnchor = true; host.parentHasAnchor = true }
        try scenario("late-filter-writer", failure: true) { _, host in host.lateWriter = true }
        try scenario("receipt-removal-failure", failure: true) { _, host in host.receiptError = true }
        try scenario("corrupt-pf-token") { root, _ in
            try Data("{\"pfToken\":\"1234\\n9999\"}".utf8).write(to: root.appendingPathComponent("Library/PrivilegedHelperTools/org.claudeguard/state/filter.json"))
        }
        let outside = base.appendingPathComponent("outside")
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        try Data("keep".utf8).write(to: outside.appendingPathComponent("untouched"))
        try scenario("symlink-leaf-unlinked-only") { root, _ in
            let cache = root.appendingPathComponent("Users/test/Library/Caches/org.claudeguard.mac")
            try FileManager.default.removeItem(at: cache)
            try FileManager.default.createSymbolicLink(at: cache, withDestinationURL: outside)
        }
        try scenario("symlink-parent-refused", failure: true) { root, _ in
            let cache = root.appendingPathComponent("Users/test/Library/Caches")
            try FileManager.default.removeItem(at: cache)
            try FileManager.default.createSymbolicLink(at: cache, withDestinationURL: outside)
        }
        let unchanged = try String(contentsOf: outside.appendingPathComponent("untouched"), encoding: .utf8)
        precondition(unchanged == "keep")
        print("PASS: \(passed) native uninstall scenarios; host networking was not modified")
    }
}
