import Foundation

/// Anonymous, explicit diagnostics only. This transport never handles ordinary
/// application traffic or supplies a browser identity to a remote service.
enum ServiceDiagnosticTransport {
    static let hosts = ["claude.ai", "api.anthropic.com"]

    static func configuration() -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = 5
        configuration.timeoutIntervalForResource = 5
        configuration.httpMaximumConnectionsPerHost = 1
        // An absent override lets Foundation generate a bundle-derived User-Agent.
        // Use an explicitly empty value; do not impersonate another application.
        configuration.httpAdditionalHeaders = ["User-Agent": "", "Accept-Language": ""]
        return configuration
    }

    static func request(host: String) -> URLRequest? {
        guard hosts.contains(host), let url = URL(string: "https://" + host + "/cdn-cgi/trace") else { return nil }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 5)
        request.httpShouldHandleCookies = false
        request.setValue("", forHTTPHeaderField: "User-Agent")
        request.setValue("", forHTTPHeaderField: "Accept-Language")
        request.setValue("text/plain", forHTTPHeaderField: "Accept")
        return request
    }
}

final class ServiceTraceDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        authentication(challenge, completion: completionHandler)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        authentication(challenge, completion: completionHandler)
    }

    private func authentication(_ challenge: URLAuthenticationChallenge,
                                completion: (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completion(challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust
                   ? .performDefaultHandling : .cancelAuthenticationChallenge, nil)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
