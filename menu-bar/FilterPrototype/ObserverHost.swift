import AppKit
import Foundation
import NetworkExtension
import SystemExtensions

private let appID = "org.v2boxkillswitch.firewallprobe"
private let dataExtensionID = appID + ".extension"
private let packetExtensionID = appID + ".packet"

private final class ActivationDelegate: NSObject, OSSystemExtensionRequestDelegate {
    private let completion: (Result<Void, Error>) -> Void
    private let approvalNeeded: () -> Void

    init(completion: @escaping (Result<Void, Error>) -> Void,
         approvalNeeded: @escaping () -> Void = {}) {
        self.completion = completion
        self.approvalNeeded = approvalNeeded
    }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        fputs("Approve the observer in System Settings when prompted.\n", stderr)
        approvalNeeded()
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        if result == .completed { completion(.success(())) }
        else { completion(.failure(HostError.rebootRequired)) }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        completion(.failure(error))
    }
}

private final class DeactivationDelegate: NSObject, OSSystemExtensionRequestDelegate {
    private let completion: (Result<Void, Error>) -> Void
    private let approvalNeeded: () -> Void
    init(completion: @escaping (Result<Void, Error>) -> Void,
         approvalNeeded: @escaping () -> Void = {}) {
        self.completion = completion
        self.approvalNeeded = approvalNeeded
    }
    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) { approvalNeeded() }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        if result == .completed { completion(.success(())) }
        else { completion(.failure(HostError.rebootRequired)) }
    }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) { completion(.failure(error)) }
}

private enum HostError: LocalizedError {
    case usage, rebootRequired
    var errorDescription: String? {
        switch self {
        case .usage: return "Usage: V2BoxFirewallObserver --activate-observer | --status | --disable-observer | --remove-observer"
        case .rebootRequired: return "macOS requires a reboot before the extension is active"
        }
    }
}

@main
final class ObserverHost: NSObject, NSApplicationDelegate {
    private static var retainedHost: ObserverHost?
    private var activationDelegate: ActivationDelegate?
    private var deactivationDelegate: DeactivationDelegate?
    private var pendingExtensionIDs: [String] = []
    private var statusItem: NSStatusItem?
    private var statusMenu: NSMenu?
    private var statusLine: NSMenuItem?

    static func main() {
        guard getuid() != 0, getuid() == geteuid() else {
            fputs("Run as the logged-in user, never with sudo.\n", stderr)
            exit(2)
        }
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let host = ObserverHost()
        retainedHost = host
        app.delegate = host
        app.run()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let args = Array(CommandLine.arguments.dropFirst())
        if args.isEmpty {
            installMenuBarControls()
            refreshMenuStatus()
            return
        }
        guard args.count == 1 else { Self.fail(HostError.usage) }
        switch args[0] {
        case "--activate-observer": activate()
        case "--status": showStatus()
        case "--disable-observer": configureFilter(enabled: false) { error in
            if let error { Self.fail(error) }
            print("Observer filter configuration disabled.")
            exit(0)
        }
        case "--remove-observer": removeFilterConfiguration()
        default: Self.fail(HostError.usage)
        }
    }

    private func showStatus() {
        let manager = NEFilterManager.shared()
        manager.loadFromPreferences { error in
            if let error { Self.fail(error) }
            let config = manager.providerConfiguration
            print("Observer enabled=\(manager.isEnabled) sockets=\(config?.filterSockets ?? false) packets=\(config?.filterPackets ?? false) data_provider=\(config?.filterDataProviderBundleIdentifier ?? "nil") packet_provider=\(config?.filterPacketProviderBundleIdentifier ?? "nil")")
            exit(0)
        }
    }

    private func activate() {
        // Default activation is flow-only; packet capture remains experimental.
        pendingExtensionIDs = [dataExtensionID]
        activateNextExtension()
    }

    private func activateNextExtension() {
        guard !pendingExtensionIDs.isEmpty else {
            configureFilter(enabled: true) { error in
                if let error { Self.fail(error) }
                print("Flow observer configuration saved. Check System Settings and systemextensionsctl to confirm it is running; unresolved test-probe flows are dropped.")
                exit(0)
            }
            return
        }
        let nextExtensionID = pendingExtensionIDs.removeFirst()
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: nextExtensionID,
                                                                 queue: .main)
        let delegate = ActivationDelegate { result in
            switch result {
            case .success: self.activateNextExtension()
            case .failure(let error): Self.fail(error)
            }
        }
        // Retained for the asynchronous request's lifetime.
        activationDelegate = delegate
        request.delegate = delegate
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    private func configureFilter(enabled: Bool, completion: @escaping (Error?) -> Void) {
        let manager = NEFilterManager.shared()
        manager.loadFromPreferences { error in
            guard error == nil else { completion(error); return }
            if enabled {
                let config = NEFilterProviderConfiguration()
                config.filterSockets = true
                config.filterPackets = false
                config.filterDataProviderBundleIdentifier = dataExtensionID
                manager.providerConfiguration = config
                manager.localizedDescription = "V2Box Read-Only Flow Observer"
                manager.grade = .firewall
            }
            manager.isEnabled = enabled
            manager.saveToPreferences { saveError in
                completion(saveError)
            }
        }
    }

    private func installMenuBarControls() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.title = "V2Box Observer"
        let menu = NSMenu()
        let status = NSMenuItem(title: "Checking observer status…", action: nil, keyEquivalent: "")
        status.isEnabled = false
        menu.addItem(status)
        menu.addItem(.separator())
        let enable = NSMenuItem(title: "Enable observer", action: #selector(enableFromMenu), keyEquivalent: "")
        enable.target = self
        menu.addItem(enable)
        let disable = NSMenuItem(title: "Disable filter", action: #selector(disableFromMenu), keyEquivalent: "")
        disable.target = self
        menu.addItem(disable)
        let emergency = NSMenuItem(title: "Emergency stop: remove filter + terminate", action: #selector(emergencyStopFromMenu), keyEquivalent: "")
        emergency.target = self
        menu.addItem(emergency)
        menu.addItem(.separator())
        let refresh = NSMenuItem(title: "Refresh status", action: #selector(refreshFromMenu), keyEquivalent: "")
        refresh.target = self
        menu.addItem(refresh)
        let quit = NSMenuItem(title: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        menu.addItem(quit)
        item.menu = menu
        statusItem = item
        statusMenu = menu
        statusLine = status
    }

    @objc private func refreshFromMenu() { refreshMenuStatus() }

    private func refreshMenuStatus() {
        NEFilterManager.shared().loadFromPreferences { [weak self] error in
            DispatchQueue.main.async {
                guard let self else { return }
                if let error { self.statusLine?.title = "Status unavailable: \(error.localizedDescription)"; return }
                let manager = NEFilterManager.shared()
                if manager.isEnabled {
                    self.statusLine?.title = "Filter config ON · extension runtime unverified"
                } else {
                    self.statusLine?.title = "Filter config OFF"
                }
            }
        }
    }

    @objc private func disableFromMenu() {
        statusLine?.title = "Disabling filter…"
        configureFilter(enabled: false) { [weak self] error in
            DispatchQueue.main.async {
                self?.statusLine?.title = error.map { "Disable failed: \($0.localizedDescription)" } ?? "Observer filter disabled"
            }
        }
    }

    @objc private func enableFromMenu() {
        statusLine?.title = "Enabling observer…"
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: dataExtensionID, queue: .main)
        let delegate = ActivationDelegate(completion: { [weak self] result in
            DispatchQueue.main.async {
                guard let self else { return }
                switch result {
                case .success:
                    self.configureFilter(enabled: true) { error in
                        DispatchQueue.main.async {
                            self.statusLine?.title = error.map { "Enable failed: \($0.localizedDescription)" } ?? "Filter config ON · extension runtime unverified"
                        }
                    }
                case .failure(let error):
                    self.statusLine?.title = "Activation failed: \(error.localizedDescription)"
                }
            }
        }, approvalNeeded: { [weak self] in
            DispatchQueue.main.async { self?.statusLine?.title = "Approve observer in System Settings…" }
        })
        activationDelegate = delegate
        request.delegate = delegate
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    @objc private func emergencyStopFromMenu() {
        statusLine?.title = "Emergency stop: disabling and removing filter…"
        configureFilter(enabled: false) { [weak self] configurationError in
            guard let self else { return }
            self.removeFilterConfiguration { removeError in
                self.deactivateExtension(dataExtensionID) { dataResult in
                    self.deactivateExtension(packetExtensionID) { packetResult in
                        DispatchQueue.main.async {
                            let deactivationErrors = [dataResult, packetResult].compactMap { result -> String? in
                                if case .failure(let error) = result { return error.localizedDescription }
                                return nil
                            }
                            var messages: [String] = []
                            if let configurationError { messages.append("disable save failed: \(configurationError.localizedDescription)") }
                            if let removeError { messages.append("preference removal failed: \(removeError.localizedDescription)") }
                            if !deactivationErrors.isEmpty { messages.append("deactivation: \(deactivationErrors.joined(separator: "; "))") }
                            self.statusLine?.title = messages.isEmpty ? "Filter removed; extensions terminated" : "Emergency stop: \(messages.joined(separator: " | "))"
                        }
                    }
                }
            }
        }
    }

    private func deactivateExtension(_ identifier: String, completion: @escaping (Result<Void, Error>) -> Void) {
        let request = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: identifier, queue: .main)
        let delegate = DeactivationDelegate(completion: completion, approvalNeeded: { [weak self] in
            DispatchQueue.main.async { self?.statusLine?.title = "Approve extension deactivation in System Settings…" }
        })
        deactivationDelegate = delegate
        request.delegate = delegate
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    private func removeFilterConfiguration() {
        let manager = NEFilterManager.shared()
        manager.loadFromPreferences { error in
            guard error == nil else { Self.fail(error!) }
            manager.removeFromPreferences { removeError in
                if let removeError { Self.fail(removeError) }
                print("Observer filter configuration removed.")
                exit(0)
            }
        }
    }

    private func removeFilterConfiguration(completion: @escaping (Error?) -> Void) {
        let manager = NEFilterManager.shared()
        manager.loadFromPreferences { error in
            guard error == nil else { completion(error); return }
            manager.removeFromPreferences { removeError in completion(removeError) }
        }
    }

    private static func fail(_ error: Error) -> Never {
        fputs("Observer setup failed: \(error.localizedDescription)\n", stderr)
        exit(1)
    }
}
