import Darwin
import Foundation

struct GuardianTrust: Codable {
    static let directory = "/Library/PrivilegedHelperTools/org.claudeguard"
    static let path = directory + "/install-trust.json"
    static let identifiers = ["org.claudeguard.mac",
                              "org.claudeguard.daemon", "org.claudeguard.offline-recovery"]

    var schemaVersion = 2
    var ownerUID: UInt32
    var hashes: [String: [String]]

    var valid: Bool {
        schemaVersion == 2 && Set(hashes.keys) == Set(Self.identifiers) && hashes.values.allSatisfy {
            !$0.isEmpty && $0.count <= 4 && Set($0).count == $0.count && $0.allSatisfy { hash in
                hash.utf8.count == 40 && hash.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
            }
        }
    }

    func requirement(_ identifier: String) -> String? {
        guard valid, Self.identifiers.contains(identifier), let values = hashes[identifier] else { return nil }
        let alternatives = values.map { "cdhash H\"\($0)\"" }.joined(separator: " or ")
        return "identifier \"\(identifier)\" and (\(alternatives))"
    }

    static func load() -> Self? {
        read(path: path)
    }

    static func loadTemplate() -> Self? {
        read(path: directory + "/install-trust-template.json")
    }

    private static func read(path: String) -> Self? {
        for path in ["/Library", "/Library/PrivilegedHelperTools", directory] {
            var metadata = stat()
            guard lstat(path, &metadata) == 0, metadata.st_uid == 0,
                  metadata.st_mode & S_IFMT == S_IFDIR, metadata.st_mode & 0o022 == 0 else { return nil }
        }
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        defer { close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0, metadata.st_uid == 0,
              metadata.st_mode & S_IFMT == S_IFREG, metadata.st_mode & 0o022 == 0,
              (1...16384).contains(metadata.st_size) else { return nil }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        guard let bytes = try? handle.read(upToCount: 16385), bytes.count <= 16384,
              let value = try? JSONDecoder().decode(Self.self, from: bytes), value.valid else { return nil }
        return value
    }

    static func selfTest() -> Bool {
        let hash = String(repeating: "a", count: 40)
        let values = Dictionary(uniqueKeysWithValues: identifiers.map { ($0, [hash]) })
        let trust = GuardianTrust(ownerUID: 501, hashes: values)
        guard trust.valid, trust.requirement("unknown") == nil,
              trust.requirement(identifiers[0])?.contains("cdhash H\"\(hash)\"") == true else { return false }
        var invalid = trust
        invalid.hashes[identifiers[0]] = [hash + "\" or always"]
        guard !invalid.valid else { return false }
        invalid = trust
        invalid.hashes.removeValue(forKey: identifiers[0])
        return !invalid.valid
    }
}
