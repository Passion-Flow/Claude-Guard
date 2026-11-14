import SwiftUI

struct GuardDropdown<Value: Hashable>: View {
    let title: String
    let selection: Value?
    let choices: [Value]
    let palette: GuardPalette
    let label: (Value) -> String
    let onSelect: (Value) -> Void
    @State private var expanded = false
    @Environment(\.isEnabled) private var enabled

    init(_ title: String, selection: Binding<Value>, choices: [Value], palette: GuardPalette,
         label: @escaping (Value) -> String) {
        self.init(title, selected: selection.wrappedValue, choices: choices, palette: palette, label: label) {
            selection.wrappedValue = $0
        }
    }

    init(_ title: String, selected: Value? = nil, choices: [Value], palette: GuardPalette,
         label: @escaping (Value) -> String, onSelect: @escaping (Value) -> Void) {
        self.title = title
        selection = selected
        self.choices = choices
        self.palette = palette
        self.label = label
        self.onSelect = onSelect
    }

    private var value: String { selection.map(label) ?? title }

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            if selection != nil {
                Text(title).font(.caption).foregroundStyle(palette.secondary)
                    .accessibilityHidden(true)
            }
            Button { expanded.toggle() } label: {
                HStack(spacing: 8) {
                    Text(value).font(.system(size: 12, weight: .medium)).lineLimit(1)
                    Spacer(minLength: 4)
                    Image(systemName: expanded ? "chevron.up" : "chevron.down")
                        .font(.system(size: 8, weight: .semibold)).foregroundStyle(palette.accent)
                }
                .padding(.horizontal, 10)
                .frame(height: 30)
                .background(expanded ? palette.highlight : palette.surface, in: RoundedRectangle(cornerRadius: 7))
                .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(expanded ? palette.accent : palette.line))
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .disabled(choices.isEmpty)
            .opacity(enabled ? 1 : 0.64)
            .accessibilityLabel(title)
            .accessibilityValue(selection == nil ? "" : value)
            .popover(isPresented: $expanded, arrowEdge: .top) {
                GuardDropdownOptions(choices: choices, selected: selection, palette: palette, label: label) { choice in
                    expanded = false
                    onSelect(choice)
                } onDismiss: {
                    expanded = false
                }
            }
            .onChange(of: enabled) { canEdit in
                if !canEdit { expanded = false }
            }
        }
    }
}

private struct GuardDropdownOptions<Value: Hashable>: View {
    let choices: [Value]
    let selected: Value?
    let palette: GuardPalette
    let label: (Value) -> String
    let onSelect: (Value) -> Void
    let onDismiss: () -> Void
    @FocusState private var focused: Value?
    @FocusState private var searchFocused: Bool
    @State private var search = ""
    @Environment(\.locale) private var locale

    private var filtered: [Value] {
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        return query.isEmpty ? choices : choices.filter {
            label($0).localizedCaseInsensitiveContains(query) || String(describing: $0).localizedCaseInsensitiveContains(query)
        }
    }

    private func tr(_ key: String) -> String {
        GuardText(key)[locale.identifier.hasPrefix("zh") ? .chinese : .english]
    }

    var body: some View {
        VStack(spacing: 6) {
            if choices.count > 12 {
                HStack(spacing: 7) {
                    Image(systemName: "magnifyingglass").foregroundStyle(palette.secondary)
                    TextField(tr("Search options"), text: $search)
                        .textFieldStyle(.plain).focused($searchFocused)
                        .onSubmit { if let first = filtered.first { onSelect(first) } }
                }
                .padding(8)
                .background(palette.canvas, in: RoundedRectangle(cornerRadius: 6))
                .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(palette.line))
            }
            if filtered.isEmpty {
                Text(tr("No matching options")).foregroundStyle(palette.secondary).padding(10)
            }
            else if choices.count > 7 {
                ScrollViewReader { proxy in
                    ScrollView { rows }.frame(height: 238)
                        .onChange(of: focused) { value in
                            if let value { proxy.scrollTo(value) }
                        }
                }
            } else {
                rows
            }
        }
        .padding(6)
        .frame(minWidth: 158, idealWidth: 196, maxWidth: 285)
        .foregroundStyle(palette.ink)
        .background(palette.surface)
        .onAppear {
            if choices.count > 12 { searchFocused = true }
            else { focused = selected ?? choices.first }
        }
        .onExitCommand(perform: onDismiss)
        .onMoveCommand { direction in
            switch direction {
            case .up: move(by: -1)
            case .down: move(by: 1)
            default: break
            }
        }
    }

    private var rows: some View {
        VStack(spacing: 3) {
            ForEach(filtered, id: \.self) { choice in
                Button { onSelect(choice) } label: {
                    HStack(spacing: 11) {
                        Text(label(choice)).font(.system(size: 12, weight: choice == selected ? .semibold : .regular))
                        Spacer(minLength: 9)
                        if choice == selected {
                            Image(systemName: "checkmark").font(.system(size: 10, weight: .semibold))
                                .foregroundStyle(palette.accent)
                        }
                    }
                    .padding(.horizontal, 10)
                    .frame(height: 29)
                    .contentShape(Rectangle())
                }
                .buttonStyle(DropdownOptionStyle(palette: palette, focused: focused == choice))
                .focusable()
                .focused($focused, equals: choice)
                .keyboardShortcut(focused == choice && !searchFocused ? KeyboardShortcut(.return, modifiers: []) : nil)
                .accessibilityAddTraits(choice == selected ? .isSelected : [])
                .id(choice)
            }
        }
    }

    private func move(by delta: Int) {
        guard let start = focused.flatMap({ filtered.firstIndex(of: $0) }) else {
            focused = filtered.first
            return
        }
        searchFocused = false
        focused = filtered[min(max(start + delta, 0), filtered.count - 1)]
    }
}

private struct DropdownOptionStyle: ButtonStyle {
    let palette: GuardPalette
    let focused: Bool
    @State private var hovering = false

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .background(focused || hovering || configuration.isPressed ? palette.highlight : Color.clear,
                        in: RoundedRectangle(cornerRadius: 6))
            .onHover { hovering = $0 }
    }
}
