import Foundation
import IOKit
import IOKit.pwr_mgt

/// The power queue is independent of XPC control. Hardware sleep is acknowledged
/// only after the shared packet fence has attempted synchronous revocation.
final class GuardianPowerObserver {
    enum Event { case canSleep, willSleep, willPowerOn, poweredOn, sleepCancelled }
    enum Failure { case registration, sealing, readiness, acknowledgment }
    // IOMessage.h's function-like macros are not imported into Swift. The
    // fixture compares these ABI values with a C probe of the installed SDK.
    private enum Message: UInt32 {
        case canSleep = 0xe0000270
        case willSleep = 0xe0000280
        case sleepCancelled = 0xe0000290
        case poweredOn = 0xe0000300
        case willPowerOn = 0xe0000320
    }

    private let fence: GuardianPacketFence
    private let queue = DispatchQueue(label: "org.claudeguard.power", qos: .userInitiated)
    private let lock = NSLock()
    private var available = false
    private var awake = false
    private var connection: io_connect_t = 0
    private var notificationPort: IONotificationPortRef?
    private var notifier: io_object_t = 0
    private let onSleep: () -> Void
    private let onWake: () -> Void
    private let onFailure: (Failure) -> Void

    init(fence: GuardianPacketFence, onSleep: @escaping () -> Void,
         onWake: @escaping () -> Void, onFailure: @escaping (Failure) -> Void) {
        self.fence = fence
        self.onSleep = onSleep
        self.onWake = onWake
        self.onFailure = onFailure
    }

    var isAwake: Bool {
        lock.lock()
        defer { lock.unlock() }
        return available && awake
    }

    private func set(available: Bool? = nil, awake: Bool) {
        lock.lock()
        if let available { self.available = available }
        self.awake = awake
        lock.unlock()
    }

    func start() -> Bool {
        do { try fence.inhibit() }
        catch { onFailure(.sealing); return false }
        return queue.sync {
            connection = IORegisterForSystemPower(Unmanaged.passUnretained(self).toOpaque(),
                &notificationPort, Self.callback, &notifier)
            guard connection != 0, let notificationPort else {
                onFailure(.registration)
                return false
            }
            IONotificationPortSetDispatchQueue(notificationPort, queue)
            do { try fence.monitoringReady() }
            catch { onFailure(.readiness); return false }
            // Any already queued sleep event runs after this registration block.
            set(available: true, awake: fence.isAwake)
            return true
        }
    }

    private static let callback: IOServiceInterestCallback = { context, _, message, argument in
        guard let context else { return }
        let observer = Unmanaged<GuardianPowerObserver>.fromOpaque(context).takeUnretainedValue()
        let event: Event
        switch Message(rawValue: message) {
        case .canSleep: event = .canSleep
        case .willSleep: event = .willSleep
        case .willPowerOn: event = .willPowerOn
        case .poweredOn: event = .poweredOn
        case .sleepCancelled: event = .sleepCancelled
        case nil: return
        }
        observer.handle(event) {
            if IOAllowPowerChange(observer.connection, Int(bitPattern: argument)) != kIOReturnSuccess {
                observer.onFailure(.acknowledgment)
            }
        }
    }

    private func handle(_ event: Event, acknowledge: () -> Void) {
        switch event {
        case .canSleep:
            acknowledge()
        case .willSleep:
            set(awake: false)
            // WillSleep is not cancellable. A failed seal remains a reported
            // failure; withholding acknowledgment cannot provide enforcement.
            defer { acknowledge() }
            do { try fence.inhibit(forSleep: true); onSleep() }
            catch { onFailure(.sealing) }
        case .willPowerOn:
            break // Network and storage are not necessarily usable yet.
        case .poweredOn, .sleepCancelled:
            guard !isAwake else { return }
            do {
                try fence.inhibit()
                try fence.monitoringReady(waking: true)
                guard fence.isAwake else { throw GuardianPacketFence.Failure.revoked }
                set(available: true, awake: true)
                onWake()
            } catch {
                set(awake: false)
                onFailure(.readiness)
            }
        }
    }

    deinit {
        if notifier != 0 { IODeregisterForSystemPower(&notifier) }
        if let notificationPort { IONotificationPortDestroy(notificationPort) }
        if connection != 0 { IOServiceClose(connection) }
    }

    #if GUARD_DIAGNOSTICS
    static var fixtureMessageValues: [UInt32] {
        [Message.canSleep, .willSleep, .willPowerOn, .poweredOn, .sleepCancelled].map(\.rawValue)
    }
    func fixtureReady() { set(available: true, awake: true) }
    func fixtureAwaitingReadiness() { set(available: true, awake: false) }
    func fixtureEvent(_ event: Event, acknowledge: () -> Void) { handle(event, acknowledge: acknowledge) }
    #endif
}
