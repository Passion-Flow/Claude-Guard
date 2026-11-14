import Foundation
import SwiftUI

@MainActor final class ServiceDiagnostics: ObservableObject {
    enum Outcome: Equatable {
        case matched, different, unavailable
        var title: GuardText {
            switch self {
            case .matched: return GuardText("Anonymous service exit matched")
            case .different: return GuardText("Anonymous service exit differs")
            case .unavailable: return GuardText("Anonymous service evidence unavailable")
            }
        }
    }
    struct Result: Identifiable {
        let id: String
        let outcome: Outcome
    }
    static let hosts = ServiceDiagnosticTransport.hosts
    @Published private(set) var checking = false
    @Published private(set) var results: [Result] = []
    @Published private(set) var checkedAt: Date?
    private var task: Task<Void, Never>?
    private var activeSession: URLSession?
    private var context: String?
    private var generation = UUID()

    private static func key(_ status: Snapshot) -> String {
        [status.session, status.serviceID ?? "", status.interface, status.expected,
         status.endpointKey ?? "", status.policyID ?? ""].joined(separator: "|")
    }

    func synchronize(_ status: Snapshot?, confirmed: Bool) {
        let next = status.flatMap { confirmed && $0.mode == "live" && $0.phase == "OPEN" ? Self.key($0) : nil }
        let expired = checkedAt.map { !(0...300).contains(Date().timeIntervalSince($0)) } ?? false
        if context != next || expired {
            stop()
            context = next
        }
    }

    func stop() {
        generation = UUID()
        task?.cancel()
        activeSession?.invalidateAndCancel()
        activeSession = nil
        task = nil
        checking = false
        results = []
        checkedAt = nil
        context = nil
    }

    func start(_ status: Snapshot) {
        guard !checking, context == Self.key(status), status.phase == "OPEN", status.mode == "live" else { return }
        let token = UUID()
        generation = token
        checking = true
        results = []
        checkedAt = nil
        let expected = status.expected
        task = Task { [weak self] in
            guard let self else { return }
            var values: [Result] = []
            for host in Self.hosts {
                let outcome = await self.probe(host: host, expected: expected)
                guard !Task.isCancelled, self.generation == token else { return }
                values.append(Result(id: host, outcome: outcome))
            }
            guard self.generation == token else { return }
            self.results = values
            self.checkedAt = Date()
            self.checking = false
            self.task = nil
        }
    }

    nonisolated static func classify(_ data: Data, expected: String) -> Outcome {
        guard data.count <= 4096, !data.contains(0), let text = String(data: data, encoding: .utf8) else { return .unavailable }
        let addresses = text.split(separator: "\n", omittingEmptySubsequences: false)
            .filter { $0.hasPrefix("ip=") }.map { String($0.dropFirst(3)) }
        guard addresses.count == 1, DetectedEndpoint.validIPv4(addresses[0]) else { return .unavailable }
        return addresses[0] == expected ? .matched : .different
    }

    private func probe(host: String, expected: String) async -> Outcome {
        guard let request = ServiceDiagnosticTransport.request(host: host) else { return .unavailable }
        let configuration = ServiceDiagnosticTransport.configuration()
        let session = URLSession(configuration: configuration, delegate: ServiceTraceDelegate(), delegateQueue: nil)
        activeSession = session
        defer {
            session.invalidateAndCancel()
            if activeSession === session { activeSession = nil }
        }
        do {
            let (bytes, response) = try await session.bytes(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200,
                  http.url?.scheme == "https", http.url?.host == host, http.expectedContentLength <= 4096 else { return .unavailable }
            var data = Data()
            for try await byte in bytes {
                guard data.count < 4096, !Task.isCancelled else { return .unavailable }
                data.append(byte)
            }
            return Self.classify(data, expected: expected)
        } catch { return .unavailable }
    }

    static func selfTest() -> Bool {
        let expected = "192.0.2.42"
        let model = ServiceDiagnostics()
        model.context = "fixture"
        model.results = [Result(id: hosts[0], outcome: .matched)]
        model.checkedAt = Date()
        model.synchronize(nil, confirmed: false)
        guard model.results.isEmpty, model.context == nil, model.checkedAt == nil, !model.checking else { return false }
        return classify(Data("ip=192.0.2.42\nloc=US\n".utf8), expected: expected) == .matched &&
            classify(Data("ip=192.0.2.99".utf8), expected: expected) == .different &&
            ["ip=192.0.2.42\nip=192.0.2.42", "ip=192.0.2.42=extra", "ip=192.0.2.\0" + "42", "empty"].allSatisfy {
                classify(Data($0.utf8), expected: expected) == .unavailable
            }
    }
}
