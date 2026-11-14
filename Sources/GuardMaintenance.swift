import AppKit
import Foundation

enum GuardMaintenance {
    @MainActor static func openPackage(_ name: String) -> Bool {
        guard ["Uninstall", "OfflineRecovery"].contains(name),
              let source = Bundle.main.url(forResource: name, withExtension: "pkg") else { return false }
        do {
            // Installer must keep its source after the app bundle is removed.
            // A user-private temporary copy also works when helper trust is gone.
            let directory = try FileManager.default.url(for: .cachesDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
                .appendingPathComponent("org.claudeguard.mac/Maintenance/" + UUID().uuidString)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            let destination = directory.appendingPathComponent(name + ".pkg")
            try FileManager.default.copyItem(at: source, to: destination)
            return NSWorkspace.shared.open(destination)
        } catch { return false }
    }
}
