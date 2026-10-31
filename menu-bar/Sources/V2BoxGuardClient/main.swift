import AppKit
import Foundation

// Client API for a future signed, root-owned XPC helper. There is intentionally
// no shell fallback. The service is not supplied/registered in this project yet.
private let serviceName = "org.v2boxkillswitch.helper"

@objc private protocol GuardXPCProtocol {
    func status(_ reply: @escaping (Data?, String?) -> Void)
    func setProtectionEnabled(_ enabled: Bool, reply: @escaping (Data?, String?) -> Void)
    func reconnectVPN(_ reply: @escaping (Data?, String?) -> Void)
}

final class GuardClient {
    func request(_ operation: String, enabled: Bool? = nil, completion: @escaping (Result<[String: String], Error>) -> Void) {
        let connection = NSXPCConnection(machServiceName: serviceName, options: [])
        connection.remoteObjectInterface = NSXPCInterface(with: GuardXPCProtocol.self)
        connection.invalidationHandler = { completion(.failure(ClientError.unavailable)) }
        connection.interruptionHandler = { completion(.failure(ClientError.unavailable)) }
        connection.resume()
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
            connection.invalidate()
            completion(.failure(ClientError.unavailable))
        }) as? GuardXPCProtocol else {
            connection.invalidate()
            completion(.failure(ClientError.unavailable))
            return
        }
        let reply: (Data?, String?) -> Void = { data, message in
            defer { connection.invalidate() }
            if let message { completion(.failure(ClientError.rejected(message))) ; return }
            guard let data,
                  let object = try? JSONSerialization.jsonObject(with: data),
                  let result = object as? [String: String] else {
                completion(.failure(ClientError.malformedReply))
                return
            }
            completion(.success(result))
        }
        switch operation {
        case "status": proxy.status(reply)
        case "toggle": proxy.setProtectionEnabled(enabled ?? false, reply: reply)
        case "reconnect": proxy.reconnectVPN(reply)
        default: connection.invalidate(); completion(.failure(ClientError.unavailable))
        }
    }

    enum ClientError: LocalizedError {
        case unavailable, malformedReply, rejected(String)
        var errorDescription: String? {
            switch self {
            case .unavailable: return "Privileged helper unavailable. No system action was performed."
            case .malformedReply: return "Helper returned an invalid status. State is unknown."
            case .rejected(let reason): return "Helper rejected the request: \(reason)"
            }
        }
    }
}

final class MenuController: NSObject, NSApplicationDelegate {
    private let client = GuardClient()
    private var item: NSStatusItem!
    private let actual = NSMenuItem(title: "Protection: UNAVAILABLE", action: nil, keyEquivalent: "")
    private let vpn = NSMenuItem(title: "VPN health: UNKNOWN", action: nil, keyEquivalent: "")
    private let toggle = NSMenuItem(title: "Enable Protection…", action: #selector(toggleProtection), keyEquivalent: "")
    private let reconnect = NSMenuItem(title: "Reconnect VPN…", action: #selector(reconnectVPN), keyEquivalent: "")

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.title = "Guard ?"
        item.button?.toolTip = "Protection state unknown until helper responds"
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "V2Box Guard", action: nil, keyEquivalent: ""))
        menu.addItem(actual); menu.addItem(vpn); menu.addItem(.separator())
        toggle.target = self; reconnect.target = self
        menu.addItem(toggle); menu.addItem(reconnect); menu.addItem(.separator())
        let refresh = NSMenuItem(title: "Refresh Status", action: #selector(refreshStatus), keyEquivalent: "r")
        refresh.target = self; menu.addItem(refresh)
        let quit = NSMenuItem(title: "Quit (does not change protection)", action: #selector(quitApp), keyEquivalent: "q")
        quit.target = self; menu.addItem(quit)
        item.menu = menu
        refreshStatus()
    }

    @objc private func refreshStatus() {
        client.request("status") { [weak self] result in
            DispatchQueue.main.async {
                guard let self else { return }
                switch result {
                case .failure(let error):
                    self.actual.title = "Protection: ERROR / UNKNOWN"
                    self.vpn.title = "VPN health: UNKNOWN"
                    self.toggle.isEnabled = false
                    self.reconnect.isEnabled = false
                    self.item.button?.title = "Guard !"
                    self.item.button?.toolTip = error.localizedDescription
                case .success(let data):
                    let state = data["state"] ?? "unknown"
                    let health = data["vpn_health"] ?? "unverified"
                    guard ["on", "off", "error"].contains(state) else {
                        self.actual.title = "Protection: ERROR / UNKNOWN"
                        self.toggle.isEnabled = false
                        self.reconnect.isEnabled = false
                        self.item.button?.title = "Guard !"
                        return
                    }
                    self.actual.title = "Protection: \(state.uppercased())"
                    self.vpn.title = "VPN health: \(health.uppercased())"
                    self.toggle.title = state == "on" ? "Disable Protection…" : "Enable Protection…"
                    // Enable must remain disabled until locally approved policy is
                    // available in the helper. Status reply can explicitly grant it.
                    self.toggle.isEnabled = data["can_toggle"] == "true"
                    self.reconnect.isEnabled = data["can_reconnect"] == "true"
                    self.item.button?.title = state == "on" ? "Guard ●" : (state == "off" ? "Guard ○" : "Guard !")
                    self.item.button?.toolTip = "PF helper-reported state: \(state); VPN health: \(health)"
                }
            }
        }
    }

    @objc private func toggleProtection() {
        let enable = actual.title != "Protection: ON"
        let alert = NSAlert()
        alert.messageText = enable ? "Enable network protection?" : "Disable protection?"
        alert.informativeText = enable
            ? "This can interrupt network access. Only a locally approved policy may be enabled."
            : "Disabling protection may allow direct internet traffic outside the VPN."
        alert.addButton(withTitle: enable ? "Enable" : "Disable")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        toggle.isEnabled = false
        client.request("toggle", enabled: enable) { [weak self] _ in DispatchQueue.main.async { self?.refreshStatus() } }
    }

    @objc private func reconnectVPN() {
        reconnect.isEnabled = false
        client.request("reconnect") { [weak self] _ in DispatchQueue.main.async { self?.refreshStatus() } }
    }

    @objc private func quitApp() { NSApp.terminate(nil) }
}

let app = NSApplication.shared
let delegate = MenuController()
app.delegate = delegate
app.run()
