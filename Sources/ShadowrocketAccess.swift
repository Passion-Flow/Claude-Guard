import AppKit
import Darwin
import Foundation

enum ShadowrocketAccess {
    private static let bookmarkKey = "shadowrocketReadOnlyBookmark"
    private static var expectedDirectory: URL {
        let home = getpwuid(getuid()).map { String(cString: $0.pointee.pw_dir) } ?? NSHomeDirectory()
        return URL(fileURLWithPath: home, isDirectory: true)
            .appendingPathComponent("Library/Group Containers/group.com.liguangming.Shadowrocket", isDirectory: true)
    }

    static func readCurrent() throws -> ShadowrocketProfile {
        var directory = expectedDirectory
        if let data = UserDefaults.standard.data(forKey: bookmarkKey) {
            var stale = false
            guard let resolved = try? URL(resolvingBookmarkData: data, options: [.withSecurityScope, .withoutUI], bookmarkDataIsStale: &stale),
                  resolved.resolvingSymlinksInPath() == expectedDirectory.resolvingSymlinksInPath(), !stale else {
                throw ShadowrocketProfile.Failure.unavailable
            }
            directory = resolved
        }
        let scoped = directory.startAccessingSecurityScopedResource()
        defer { if scoped { directory.stopAccessingSecurityScopedResource() } }
        return try ShadowrocketProfile.readCurrent(base: directory)
    }

    @MainActor static func requestReadAccess(language: GuardLanguage, completion: @escaping (Bool) -> Void) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.canCreateDirectories = false
        panel.directoryURL = expectedDirectory
        panel.prompt = GuardText("Allow read access")[language]
        panel.message = GuardText("Allow Claude Guard to read connection metadata from this Shadowrocket folder. Passwords and subscription payloads are not decoded.")[language]
        panel.begin { response in
            guard response == .OK, let url = panel.url,
                  url.resolvingSymlinksInPath() == expectedDirectory.resolvingSymlinksInPath(),
                  let bookmark = try? url.bookmarkData(options: [.withSecurityScope, .securityScopeAllowOnlyReadAccess],
                                                       includingResourceValuesForKeys: nil, relativeTo: nil) else {
                completion(false); return
            }
            UserDefaults.standard.set(bookmark, forKey: bookmarkKey)
            completion(true)
        }
    }
}
