import AppKit
import SwiftUI

@MainActor
enum GuardPreviews {
    static func render(to directory: URL) throws {
        NSApplication.shared.setActivationPolicy(.prohibited)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let controller = GuardController(preview: true)
        try save(GuardWindow(controller: controller, language: .constant(.chinese),
                             appearance: .constant(.light), demo: true)
            .frame(width: 1060, height: 1100).environment(\.colorScheme, .light),
            to: directory.appendingPathComponent("Claude-Guard-Overview-ZH.png"))
        try save(GuardWindow(controller: controller, language: .constant(.english),
                             appearance: .constant(.dark), demo: true)
            .frame(width: 1060, height: 1100).environment(\.colorScheme, .dark),
            to: directory.appendingPathComponent("Claude-Guard-Overview-EN.png"))
        try save(GuardWindow(controller: controller, language: .constant(.english),
                             appearance: .constant(.dark), pane: .path, demo: true)
            .frame(width: 1060, height: 1600).environment(\.colorScheme, .dark),
            to: directory.appendingPathComponent("Claude-Guard-Traffic-Path-EN.png"))
        try save(GuardWindow(controller: controller, language: .constant(.chinese),
                             appearance: .constant(.light), pane: .path, demo: true)
            .frame(width: 1060, height: 1600).environment(\.colorScheme, .light),
            to: directory.appendingPathComponent("Claude-Guard-Traffic-Path-ZH.png"))
        try save(GuardMenu(controller: controller, language: .chinese, demo: true)
            .environment(\.colorScheme, .dark),
            to: directory.appendingPathComponent("Claude-Guard-Menu.png"))
        for (language, appearance) in [(GuardLanguage.chinese, GuardAppearance.light), (.english, .dark)] {
            try save(RecoveryWindow(language: .constant(language), appearance: .constant(appearance))
                .frame(width: 620, height: 380).environment(\.colorScheme, appearance.scheme ?? .light),
                to: directory.appendingPathComponent("Claude-Guard-Recovery-" + language.rawValue + ".png"))
        }
    }

    private static func save<Content: View>(_ content: Content, to url: URL) throws {
        let renderer = ImageRenderer(content: content)
        renderer.scale = 1.5
        guard let image = renderer.cgImage,
              let data = NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        try data.write(to: url, options: .atomic)
    }
}
