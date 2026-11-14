import AppKit
import Foundation
import Network
import SwiftUI

enum ExternalDiagnosticSite {
    case netCoffee, browserScore

    var url: URL {
        switch self {
        case .netCoffee: return URL(string: "https://ip.net.coffee/claude/")!
        case .browserScore: return URL(string: "https://fuck-claude.com/")!
        }
    }
}

struct BrowserObservation: Codable, Equatable {
    let privateHost: Int
    let publicHost: Int
    let approvedReflexive: Int
    let otherReflexive: Int
    let relay: Int
    let unknown: Int
    let complete: Bool
    let generation: String
    let phase: String

    var valid: Bool {
        let counts = [privateHost, publicHost, approvedReflexive, otherReflexive, relay, unknown]
        return counts.allSatisfy { (0...128).contains($0) } && counts.reduce(0, +) <= 128
    }

    var title: GuardText {
        if otherReflexive > 0 { return GuardText("Browser exit differs") }
        if publicHost > 0 { return GuardText("Public host address exposed") }
        if complete && approvedReflexive > 0 { return GuardText("Browser exit sample matched") }
        return GuardText("Browser evidence unavailable")
    }
}

struct BrowserEvidence {
    let observation: BrowserObservation
    let checkedAt: Date

    var summary: GuardText { observation.title }
}

/// A browser observation is diagnostic evidence. It cannot authorize a policy change.
@MainActor
final class BrowserDiagnostics: ObservableObject {
    @Published private(set) var evidence: BrowserEvidence?
    @Published private(set) var running = false
    @Published private(set) var error: GuardText?

    private var listener: NWListener?
    private var connections: [UUID: NWConnection] = [:]
    private var timer: Timer?
    private var deadline = Date.distantPast
    private var context: Context?
    private var phase = "LOCKED"
    private var token = ""
    private var generation = ""
    private var port: UInt16 = 0
    private var language: GuardLanguage = .english
    private var appearance: GuardAppearance = .system

    private struct Context: Equatable {
        let session: String
        let interface: String
        let expected: String
        let service: String?
        let endpoint: String?
        let policy: String?

        init(_ status: Snapshot) {
            session = status.session
            interface = status.interface
            expected = status.expected
            service = status.serviceID
            endpoint = status.endpointKey
            policy = status.policyID
        }
    }

    func synchronize(_ status: Snapshot?, confirmed: Bool) {
        guard running else { return }
        guard confirmed, let status, context == Context(status), Date() < deadline else {
            stop()
            return
        }
        if phase != status.phase {
            phase = status.phase
            generation = UUID().uuidString
            evidence = nil
        }
    }

    func start(_ status: Snapshot, language: GuardLanguage, appearance: GuardAppearance) {
        stop()
        guard status.phase == "OPEN", status.mode == "live", status.policyID == GuardPolicy.id,
              GuardConfiguration.validIPv4(status.expected), GuardConfiguration.validInterface(status.interface) else { return }
        self.language = language
        self.appearance = appearance
        context = Context(status)
        phase = status.phase
        token = UUID().uuidString.lowercased() + UUID().uuidString.lowercased()
        generation = UUID().uuidString
        deadline = Date().addingTimeInterval(300)
        error = nil
        do {
            let parameters = NWParameters.tcp
            parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
            let listener = try NWListener(using: parameters)
            self.listener = listener
            running = true
            listener.newConnectionHandler = { [weak self] connection in
                Task { @MainActor in self?.accept(connection) }
            }
            listener.stateUpdateHandler = { [weak self, weak listener] state in
                Task { @MainActor in
                    guard let self, self.listener === listener else { return }
                    switch state {
                    case .ready:
                        guard let port = listener?.port?.rawValue else { self.stop(); return }
                        self.port = port
                        if let url = URL(string: "http://127.0.0.1:\(port)/\(self.token)/") {
                            NSWorkspace.shared.open(url)
                        }
                    case .failed:
                        self.stop()
                        self.error = GuardText("The local browser test could not start.")
                    default: break
                    }
                }
            }
            timer = Timer.scheduledTimer(withTimeInterval: 300, repeats: false) { [weak self] _ in
                Task { @MainActor in self?.stop() }
            }
            listener.start(queue: .main)
        } catch {
            stop()
            self.error = GuardText("The local browser test could not start.")
        }
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        listener?.cancel()
        listener = nil
        for connection in connections.values { connection.cancel() }
        connections.removeAll()
        context = nil
        token = ""
        generation = ""
        port = 0
        running = false
        evidence = nil
    }

    private func accept(_ connection: NWConnection) {
        guard running, Date() < deadline, connections.count < 8 else { connection.cancel(); return }
        let id = UUID()
        connections[id] = connection
        connection.start(queue: .main)
        receive(connection, id: id, buffered: Data())
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
            self?.close(id)
        }
    }

    private func close(_ id: UUID) {
        connections.removeValue(forKey: id)?.cancel()
    }

    private func receive(_ connection: NWConnection, id: UUID, buffered: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, complete, error in
            Task { @MainActor in
                guard let self, self.connections[id] != nil else { return }
                var bytes = buffered
                if let data { bytes.append(data) }
                guard bytes.count <= 12288, error == nil else { self.close(id); return }
                switch BrowserRequest.parse(bytes) {
                case .incomplete:
                    if complete { self.close(id) }
                    else { self.receive(connection, id: id, buffered: bytes) }
                case .invalid:
                    self.respond(connection, id: id, status: 400, type: "text/plain", body: Data())
                case .request(let request):
                    self.handle(request, connection: connection, id: id)
                }
            }
        }
    }

    private func handle(_ request: BrowserRequest, connection: NWConnection, id: UUID) {
        let origin = "http://127.0.0.1:\(port)"
        let prefix = "/\(token)/"
        guard running, Date() < deadline, request.headers["host"] == "127.0.0.1:\(port)",
              request.path.hasPrefix(prefix) else {
            respond(connection, id: id, status: 410, type: "text/plain", body: Data())
            return
        }
        let resource = String(request.path.dropFirst(prefix.count))
        var body = Data()
        var type = "application/json"
        if request.method == "GET", request.body.isEmpty {
            switch resource {
            case "config":
                generation = UUID().uuidString
                evidence = nil
                let keys = ["Browser network check", "Run browser check", "Checking browser…",
                            "Browser evidence unavailable", "Browser exit differs", "Public host address exposed",
                            "Browser exit sample matched", "Browser test notice", "Browser test scope"]
                let strings = Dictionary(uniqueKeysWithValues: keys.map { ($0, GuardText($0)[language]) })
                let config: [String: Any] = ["expected": context?.expected ?? "", "generation": generation,
                                            "phase": phase, "language": language.rawValue,
                                            "appearance": appearance.rawValue, "strings": strings]
                body = (try? JSONSerialization.data(withJSONObject: config)) ?? Data()
            case "", "webrtc.js", "webrtc.css":
                let name = resource.isEmpty ? "webrtc.html" : resource
                guard let url = Bundle.main.url(forResource: name, withExtension: nil, subdirectory: "BrowserDiagnostics"),
                      let contents = try? Data(contentsOf: url) else {
                    respond(connection, id: id, status: 404, type: "text/plain", body: Data())
                    return
                }
                body = contents
                type = name.hasSuffix(".html") ? "text/html" : name.hasSuffix(".css") ? "text/css" : "text/javascript"
            default:
                respond(connection, id: id, status: 404, type: "text/plain", body: Data())
                return
            }
        } else if request.method == "POST", resource == "result", request.headers["origin"] == origin,
                  request.headers["content-type"] == "application/json",
                  let report = try? JSONDecoder().decode(BrowserObservation.self, from: request.body),
                  record(report) {
            body = Data("{}".utf8)
        } else {
            respond(connection, id: id, status: 400, type: "text/plain", body: Data())
            return
        }
        respond(connection, id: id, status: 200, type: type, body: body)
    }

    private func record(_ report: BrowserObservation) -> Bool {
        guard running, context != nil, Date() < deadline, report.valid,
              report.generation == generation, report.phase == phase else { return false }
        generation = UUID().uuidString
        evidence = BrowserEvidence(observation: report, checkedAt: Date())
        return true
    }

    static func selfTest() -> Bool {
        let line = "fixture|OPEN|100|utun6|8.8.8.8|8.8.8.8|probe-ok|0|live|1|||" + GuardPolicy.id
        guard let open = Snapshot(line),
              let locked = Snapshot(line.replacingOccurrences(of: "|OPEN|", with: "|LOCKED|")) else { return false }
        let diagnostics = BrowserDiagnostics()
        diagnostics.running = true
        diagnostics.context = Context(open)
        diagnostics.phase = "OPEN"
        diagnostics.deadline = Date().addingTimeInterval(60)
        diagnostics.generation = "fixture"
        func report(_ generation: String) -> BrowserObservation {
            BrowserObservation(privateHost: 0, publicHost: 0, approvedReflexive: 1,
                               otherReflexive: 0, relay: 0, unknown: 0, complete: true,
                               generation: generation, phase: "OPEN")
        }
        let old = report("fixture")
        guard diagnostics.record(old), !diagnostics.record(old) else { return false }
        let beforeRecovery = report(diagnostics.generation)
        diagnostics.synchronize(locked, confirmed: true)
        diagnostics.synchronize(open, confirmed: true)
        guard !diagnostics.record(beforeRecovery), diagnostics.evidence == nil,
              diagnostics.record(report(diagnostics.generation)) else { return false }
        diagnostics.deadline = Date.distantPast
        guard !diagnostics.record(report(diagnostics.generation)) else { return false }
        diagnostics.stop()
        return !diagnostics.running && diagnostics.evidence == nil
    }

    private func respond(_ connection: NWConnection, id: UUID, status: Int, type: String, body: Data) {
        let headers = ["HTTP/1.1 \(status) Guard", "Content-Type: \(type); charset=utf-8", "Content-Length: \(body.count)",
                       "Connection: close", "Cache-Control: no-store", "Referrer-Policy: no-referrer",
                       "X-Content-Type-Options: nosniff",
                       "Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"]
        var response = Data((headers.joined(separator: "\r\n") + "\r\n\r\n").utf8)
        response.append(body)
        connection.send(content: response, completion: .contentProcessed { [weak self] _ in
            Task { @MainActor in self?.close(id) }
        })
    }
}

struct BrowserRequest {
    enum ParseResult { case incomplete, invalid, request(BrowserRequest) }
    let method: String
    let path: String
    let headers: [String: String]
    let body: Data

    static func parse(_ data: Data) -> ParseResult {
        guard let boundary = data.range(of: Data("\r\n\r\n".utf8)) else {
            return data.count > 4096 ? .invalid : .incomplete
        }
        guard boundary.lowerBound <= 4096,
              let head = String(data: data[..<boundary.lowerBound], encoding: .ascii) else { return .invalid }
        let rows = head.components(separatedBy: "\r\n")
        let first = rows[0].split(separator: " ", omittingEmptySubsequences: false)
        guard first.count == 3, first[2] == "HTTP/1.1", ["GET", "POST"].contains(first[0]),
              first[1].hasPrefix("/"), !first[1].contains("#"), !first[1].contains("?") else { return .invalid }
        var headers: [String: String] = [:]
        for row in rows.dropFirst() {
            guard let colon = row.firstIndex(of: ":"), colon != row.startIndex else { return .invalid }
            let name = String(row[..<colon]).lowercased()
            let value = row[row.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            guard name.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }),
                  headers[name] == nil else { return .invalid }
            headers[name] = value
        }
        guard headers["host"] != nil, headers["transfer-encoding"] == nil else { return .invalid }
        let lengthText = headers["content-length"] ?? "0"
        guard let length = Int(lengthText), String(length) == lengthText, (0...4096).contains(length) else { return .invalid }
        let body = Data(data[boundary.upperBound...])
        if body.count < length { return .incomplete }
        guard body.count == length else { return .invalid }
        return .request(BrowserRequest(method: String(first[0]), path: String(first[1]), headers: headers, body: body))
    }

    static func selfTest() -> Bool {
        let valid = Data("POST /session/result HTTP/1.1\r\nHost: 127.0.0.1:1234\r\nContent-Length: 2\r\n\r\n{}".utf8)
        guard case .request(let request) = parse(valid), request.body == Data("{}".utf8) else { return false }
        guard case .incomplete = parse(valid.dropLast()) else { return false }
        for head in [
            "Host: one\r\nHost: two\r\nContent-Length: 0",
            "Host: one\r\nTransfer-Encoding: chunked",
            "Host: one\r\nContent-Length: -1",
            "Host: one\r\nContent-Length: 4097",
            "Host: one\r\nContent-Length: 0\r\n folded: value",
        ] {
            guard case .invalid = parse(Data("POST /session/result HTTP/1.1\r\n\(head)\r\n\r\n".utf8)) else { return false }
        }
        guard case .invalid = parse(valid + Data("GET / HTTP/1.1\r\n\r\n".utf8)) else { return false }
        let empty = BrowserObservation(privateHost: 1, publicHost: 0, approvedReflexive: 0,
                                       otherReflexive: 0, relay: 1, unknown: 0, complete: true,
                                       generation: "fixture", phase: "LOCKED")
        let invalid = BrowserObservation(privateHost: -1, publicHost: 0, approvedReflexive: 0,
                                         otherReflexive: 0, relay: 0, unknown: 0, complete: true,
                                         generation: "fixture", phase: "LOCKED")
        return empty.valid && !invalid.valid && empty.title == GuardText("Browser evidence unavailable")
    }
}
