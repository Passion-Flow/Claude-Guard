import Foundation

@main struct ServiceTransportFixture {
    static func main() async throws {
        guard CommandLine.arguments.count == 2, let base = URL(string: CommandLine.arguments[1]),
              base.scheme == "http", base.host == "127.0.0.1" else { fatalError("loopback-fixture-only") }
        for invalid in ["", "example.invalid", "claude.ai.example.invalid", "claude.ai@localhost", "claude.ai/path"] {
            precondition(ServiceDiagnosticTransport.request(host: invalid) == nil)
        }
        let configuration = ServiceDiagnosticTransport.configuration()
        precondition(configuration.httpCookieStorage == nil && configuration.urlCredentialStorage == nil && configuration.urlCache == nil)
        let session = URLSession(configuration: configuration, delegate: ServiceTraceDelegate(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        // A default session is a positive control for Foundation-generated headers.
        let baseline = URLSession(configuration: .ephemeral)
        _ = try await baseline.data(from: base.appendingPathComponent("baseline"))
        baseline.invalidateAndCancel()
        for path in ["first", "second", "redirect", "authentication"] {
            var request = ServiceDiagnosticTransport.request(host: "claude.ai")!
            precondition(request.url?.scheme == "https" && request.url?.query == nil)
            // Only this separately compiled fixture replaces the fixed remote URL.
            request.url = base.appendingPathComponent(path)
            do {
                let (_, response) = try await session.data(for: request)
                let code = (response as! HTTPURLResponse).statusCode
                precondition(code == (path == "redirect" ? 302 : path == "authentication" ? 401 : 200))
            } catch {
                guard path == "authentication" else { throw error }
            }
        }
    }
}
