import Foundation
import Security

@objc protocol IdentityFixtureProtocol {
    func hello(withReply reply: @escaping (String) -> Void)
}

final class IdentityFixtureService: NSObject, IdentityFixtureProtocol {
    func hello(withReply reply: @escaping (String) -> Void) { reply("authenticated") }
}

final class IdentityFixtureDelegate: NSObject, NSXPCListenerDelegate {
    let requirement: String
    init(_ requirement: String) { self.requirement = requirement }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.setCodeSigningRequirement(requirement)
        connection.exportedInterface = NSXPCInterface(with: IdentityFixtureProtocol.self)
        connection.exportedObject = IdentityFixtureService()
        connection.resume()
        return true
    }
}

@main enum IdentityFixture {
    static func exchange(client: String, server: String) -> Bool {
        let listener = NSXPCListener.anonymous()
        let delegate = IdentityFixtureDelegate(client)
        listener.delegate = delegate
        listener.setConnectionCodeSigningRequirement(client)
        listener.resume()
        defer { listener.invalidate() }
        let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        connection.remoteObjectInterface = NSXPCInterface(with: IdentityFixtureProtocol.self)
        connection.setCodeSigningRequirement(server)
        connection.resume()
        defer { connection.invalidate() }
        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var received = false
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in semaphore.signal() }) as? IdentityFixtureProtocol else { return false }
        proxy.hello { value in
            lock.lock()
            received = value == "authenticated"
            lock.unlock()
            semaphore.signal()
        }
        _ = semaphore.wait(timeout: .now() + 4)
        lock.lock()
        defer { lock.unlock() }
        return withExtendedLifetime(delegate) { received }
    }

    static func main() {
        DispatchQueue.global().async {
            var code: SecCode?
            var staticCode: SecStaticCode?
            var information: CFDictionary?
            guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
                  SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
                  SecCodeCopySigningInformation(staticCode, [], &information) == errSecSuccess,
                  let values = information as? [String: Any],
                  let identifier = values[kSecCodeInfoIdentifier as String] as? String,
                  let data = values[kSecCodeInfoUnique as String] as? Data else { exit(1) }
            let hash = data.map { String(format: "%02x", $0) }.joined()
            let good = "identifier \"\(identifier)\" and cdhash H\"\(hash)\""
            let bad = "identifier \"\(identifier)\" and cdhash H\"\(String(repeating: "0", count: 40))\""
            guard exchange(client: good, server: good), !exchange(client: bad, server: good),
                  !exchange(client: good, server: bad) else { exit(1) }
            print("PASS: pinned ad-hoc XPC identity accepts its match and rejects mismatched callers and servers")
            exit(0)
        }
        dispatchMain()
    }
}
