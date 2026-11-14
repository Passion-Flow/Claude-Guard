import Foundation

enum GuardianConsole {
    /// Explicit administrator action using the same authenticated XPC operation
    /// as the dashboard. It cannot approve a new route or grant OPEN directly.
    static func resume(uid: UInt32, exchange: (GuardianRequest) -> GuardianResponse) -> Int32 {
        guard uid == 0 else { return 77 }
        let state = exchange(GuardianRequest(.state))
        guard state.code == 0 else { return state.code }
        guard state.canResume else { return 82 }
        guard let revision = state.controlRevision, UUID(uuidString: revision) != nil else { return 74 }
        var session = UUID().uuidString.lowercased()
        if state.active && !state.paused,
           let current = state.status?.components(separatedBy: "|").first,
           UUID(uuidString: current) != nil { session = current }
        return exchange(GuardianRequest(.resume, session: session,
                        controlRevision: revision, userInitiated: true)).code
    }

    #if GUARD_DIAGNOSTICS
    static func selfTest() -> Bool {
        let revision = UUID().uuidString
        let session = UUID().uuidString.lowercased()
        var state = GuardianResponse(code: 0)
        state.canResume = true
        state.controlRevision = revision
        state.active = true
        state.status = session + "|OPEN"
        var requests: [GuardianRequest] = []
        func exchange(_ request: GuardianRequest) -> GuardianResponse {
            requests.append(request)
            return request.operation == .state ? state : GuardianResponse(code: 0)
        }
        guard resume(uid: 501, exchange: exchange) == 77, requests.isEmpty,
              resume(uid: 0, exchange: exchange) == 0, requests.count == 2,
              requests[1].operation == .resume, requests[1].session == session,
              requests[1].controlRevision == revision, requests[1].userInitiated == true else { return false }
        requests = []; state.paused = true
        guard resume(uid: 0, exchange: exchange) == 0, requests.count == 2,
              requests[1].session != session,
              requests[1].session.flatMap(UUID.init(uuidString:)) != nil else { return false }
        requests = []; state.canResume = false
        guard resume(uid: 0, exchange: exchange) == 82, requests.count == 1 else { return false }
        requests = []; state.canResume = true; state.controlRevision = nil
        guard resume(uid: 0, exchange: exchange) == 74, requests.count == 1 else { return false }
        requests = []; state.code = 78
        return resume(uid: 0, exchange: exchange) == 78 && requests.count == 1
    }
    #endif
}

enum GuardianClient {
    static func send(_ request: GuardianRequest, recovery: Bool = false) -> GuardianResponse {
        guard GuardianIdentity.currentProcessMatches(GuardianIdentity.application) else { return GuardianResponse(code: 78) }
        if recovery && ![.hello, .state, .restore].contains(request.operation) { return GuardianResponse(code: 65) }
        let channel = recovery ? GuardianIdentity.recoveryChannel : GuardianIdentity.daemon
        let response = connect(request, channel: channel, identity: GuardianIdentity.daemon)
        if recovery && response.code == 74 {
            return connect(request, channel: GuardianIdentity.recoveryDaemon, identity: GuardianIdentity.recoveryDaemon)
        }
        return response
    }

    private static func connect(_ request: GuardianRequest, channel: String, identity: String) -> GuardianResponse {
        guard let requirement = GuardianIdentity.requirement(identity) else { return GuardianResponse(code: 78) }
        let connection = NSXPCConnection(machServiceName: channel, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: GuardianProtocol.self)
        connection.setCodeSigningRequirement(requirement)
        connection.resume()
        defer { connection.invalidate() }

        // Authenticate a non-secret reply before sending a route, key or authorization form.
        let hello = exchange(GuardianRequest(.hello), authorization: Data(), connection: connection, timeout: 5)
        guard hello.code == 0, hello.wireVersion == GuardianWire.version else { return hello }
        if request.operation == .hello { return hello }
        let timeout: Double = request.operation == .restore ? 45 : 15
        let initial = exchange(request, authorization: Data(), connection: connection, timeout: timeout)
        if request.operation == .state { return initial }
        guard initial.code == 77 else { return initial }
        return GuardianAuthorization.withExternalForm {
            exchange(request, authorization: $0, connection: connection, timeout: timeout)
        } ?? GuardianResponse(code: 77)
    }

    private static func exchange(_ request: GuardianRequest, authorization: Data,
                                 connection: NSXPCConnection, timeout: Double) -> GuardianResponse {
        guard let data = try? JSONEncoder().encode(request), data.count <= 16384 else { return GuardianResponse(code: 65) }
        let box = GuardianReplyBox()
        connection.invalidationHandler = { box.finish(GuardianResponse(code: 74)) }
        connection.interruptionHandler = { box.finish(GuardianResponse(code: 74)) }
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
            box.finish(GuardianResponse(code: 74))
        }) as? GuardianProtocol else { return GuardianResponse(code: 74) }
        proxy.submit(data, authorization: authorization) { bytes in
            guard bytes.count <= 131072, let response = try? JSONDecoder().decode(GuardianResponse.self, from: bytes),
                  response.wireVersion == GuardianWire.version else { box.finish(GuardianResponse(code: 74)); return }
            if request.operation != .hello, [0, 79].contains(response.code),
               response.controlRevision.flatMap(UUID.init(uuidString:)) == nil {
                box.finish(GuardianResponse(code: 74)); return
            }
            box.finish(response)
        }
        guard box.semaphore.wait(timeout: .now() + timeout) == .success else { return GuardianResponse(code: 74) }
        return box.result()
    }
}
