import AppKit
import Foundation

// Client API for a future signed, root-owned XPC helper. There is intentionally
// no shell fallback. The service is not supplied/registered in this project yet.
private let serviceName = "org.v2boxkillswitch.helper"

private final class CompletionGate {
    private let lock = NSLock()
    private var finished = false
    var pending: Bool {
        lock.lock(); defer { lock.unlock() }
        return !finished
    }
    func claim() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if finished { return false }
        finished = true
        return true
    }
}

final class GuardClient {
    func request(_ operation: String, enabled: Bool? = nil, authorization: Data? = nil,
                 completion: @escaping (Result<[String: String], Error>) -> Void) {
        guard #available(macOS 13.0, *),
              let hash = Bundle.main.object(forInfoDictionaryKey: "GuardHelperCDHash") as? String,
              let pin = try? PeerPin(hash) else {
            completion(.failure(ClientError.unavailable))
            return
        }
        let connection = NSXPCConnection(machServiceName: serviceName, options: .privileged)
        do { try pin.enforce(on: connection) }
        catch {
            connection.invalidate()
            completion(.failure(ClientError.unavailable))
            return
        }
        connection.remoteObjectInterface = NSXPCInterface(with: GuardXPCProtocol.self)
        let gate = CompletionGate()
        let finish: (Result<[String: String], Error>) -> Void = { result in
            guard gate.claim() else { return }
            connection.invalidationHandler = nil
            connection.interruptionHandler = nil
            connection.invalidate()
            completion(result)
        }
        connection.invalidationHandler = { finish(.failure(ClientError.unavailable)) }
        connection.interruptionHandler = { finish(.failure(ClientError.unavailable)) }
        DispatchQueue.global().asyncAfter(deadline: .now() + 8) {
            finish(.failure(ClientError.unavailable))
        }
        connection.resume()
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
            finish(.failure(ClientError.unavailable))
        }) as? GuardXPCProtocol else {
            finish(.failure(ClientError.unavailable))
            return
        }
        let reply: (Data?, String?) -> Void = { data, message in
            if let message { finish(.failure(ClientError.rejected(message))) ; return }
            guard let data,
                  let object = try? JSONSerialization.jsonObject(with: data),
                  let result = object as? [String: String] else {
                finish(.failure(ClientError.malformedReply))
                return
            }
            finish(.success(result))
        }
        switch operation {
        case "status": proxy.status(reply)
        case "toggle", "authorization":
            guard let authorization else {
                finish(.failure(ClientError.rejected("Administrator authorization is required.")))
                return
            }
            // Verify a signed response on this SAME connection before sending
            // the sensitive authorization form. A service name alone is not trust.
            proxy.status { data, error in
                guard gate.pending else { return }
                guard error == nil, let data,
                      let object = try? JSONSerialization.jsonObject(with: data),
                      let status = object as? [String: String],
                      (operation == "authorization" || status[(enabled == true) ? "can_enable" : "can_disable"] == "true") else {
                    finish(.failure(ClientError.rejected("Helper did not confirm this operation is available.")))
                    return
                }
                if operation == "authorization" {
                    proxy.checkAuthorization(authorization, reply: reply)
                } else {
                    proxy.setProtectionEnabled(enabled ?? false, authorization: authorization, reply: reply)
                }
            }
        case "reconnect": proxy.reconnectVPN(reply)
        default: finish(.failure(ClientError.unavailable))
        }
    }

    enum ClientError: LocalizedError {
        case unavailable, malformedReply, rejected(String)
        var errorDescription: String? {
            switch self {
            case .unavailable: return "Helper unavailable or timed out. Action outcome and protection state are unknown."
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
    private let mode = NSMenuItem(title: "Policy: UNKNOWN", action: nil, keyEquivalent: "")
    private let toggle = NSMenuItem(title: "Enable Protection…", action: #selector(enableProtection), keyEquivalent: "")
    private let disable = NSMenuItem(title: "Disable Protection…", action: #selector(disableProtection), keyEquivalent: "")
    private var requestGeneration = 0
    private let reconnect = NSMenuItem(title: "Reconnect VPN…", action: #selector(reconnectVPN), keyEquivalent: "")

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.title = "Guard ?"
        item.button?.toolTip = "Protection state unknown until helper responds"
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "V2Box Guard", action: nil, keyEquivalent: ""))
        menu.addItem(actual); menu.addItem(mode); menu.addItem(vpn); menu.addItem(.separator())
        toggle.target = self; disable.target = self; reconnect.target = self
        toggle.isEnabled = false; disable.isEnabled = false; reconnect.isEnabled = false
        menu.addItem(toggle); menu.addItem(disable); menu.addItem(reconnect); menu.addItem(.separator())
        let authorize = NSMenuItem(title: "Verify Administrator Access…", action: #selector(verifyAuthorization), keyEquivalent: "")
        authorize.target = self; menu.addItem(authorize)
        let refresh = NSMenuItem(title: "Refresh Status", action: #selector(refreshStatus), keyEquivalent: "r")
        refresh.target = self; menu.addItem(refresh)
        let quit = NSMenuItem(title: "Quit (does not change protection)", action: #selector(quitApp), keyEquivalent: "q")
        quit.target = self; menu.addItem(quit)
        item.menu = menu
        refreshStatus()
    }

    @objc private func refreshStatus() {
        requestGeneration += 1
        let generation = requestGeneration
        client.request("status") { [weak self] result in
            DispatchQueue.main.async {
                guard let self, generation == self.requestGeneration else { return }
                switch result {
                case .failure(let error):
                    self.actual.title = "Protection: ERROR / UNKNOWN"
                    self.vpn.title = "VPN health: UNKNOWN"
                    self.mode.title = "Policy: UNKNOWN"
                    self.toggle.isEnabled = false
                    self.disable.isEnabled = false
                    self.reconnect.isEnabled = false
                    self.item.button?.title = "Guard !"
                    self.item.button?.toolTip = error.localizedDescription
                case .success(let data):
                    let state = data["state"] ?? "unknown"
                    let health = data["vpn_health"] ?? "unverified"
                    guard ["on", "off", "error"].contains(state) else {
                        self.actual.title = "Protection: ERROR / UNKNOWN"
                        self.toggle.isEnabled = false
                        self.disable.isEnabled = false
                        self.reconnect.isEnabled = false
                        self.item.button?.title = "Guard !"
                        return
                    }
                    self.actual.title = "Protection: \(state.uppercased())"
                    self.vpn.title = "VPN health: \(health.uppercased())"
                    self.mode.title = data["policy_mode"] == "quarantine"
                        ? "Policy: QUARANTINE — approval required"
                        : "Policy: \((data["policy_mode"] ?? "unknown").uppercased())"
                    self.toggle.title = "Enable Protection…"
                    // Enable must remain disabled until locally approved policy is
                    // available in the helper. Status reply can explicitly grant it.
                    self.toggle.isEnabled = data["can_enable"] == "true" && state != "on"
                    // Recovery remains separately available when the helper can
                    // remove our rules even if enforcement verification failed.
                    self.disable.isEnabled = data["can_disable"] == "true"
                    self.reconnect.isEnabled = data["can_reconnect"] == "true"
                    self.item.button?.title = state == "on" ? "Guard ●" : (state == "off" ? "Guard ○" : "Guard !")
                    self.item.button?.toolTip = "PF helper-reported state: \(state); VPN health: \(health)"
                }
            }
        }
    }

    @objc private func verifyAuthorization() {
        do {
            let session = try AuthorizationSession()
            client.request("authorization", authorization: session.externalData) { [weak self, session] result in
                withExtendedLifetime(session) {
                    DispatchQueue.main.async {
                        let alert = NSAlert()
                        switch result {
                        case .success(let data) where data["authorized"] == "true":
                            alert.messageText = "Administrator access verified"
                            alert.informativeText = "The helper accepted authorization. No firewall change was requested."
                        case .failure(let error):
                            alert.messageText = "Authorization not verified"
                            alert.informativeText = error.localizedDescription
                        default:
                            alert.messageText = "Authorization not verified"
                            alert.informativeText = "Unexpected helper response. No firewall change was requested."
                        }
                        alert.addButton(withTitle: "OK"); alert.runModal()
                        self?.refreshStatus()
                    }
                }
            }
        } catch { actionFinished(.failure(error)) }
    }

    @objc private func enableProtection() { changeProtection(enable: true) }
    @objc private func disableProtection() { changeProtection(enable: false) }

    private func changeProtection(enable: Bool) {
        let alert = NSAlert()
        alert.messageText = enable ? "Enable network protection?" : "Disable protection?"
        alert.informativeText = enable
            ? "This can interrupt network access. Only a locally approved policy may be enabled."
            : "Disabling protection may allow direct internet traffic outside the VPN."
        alert.addButton(withTitle: enable ? "Enable" : "Disable")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        requestGeneration += 1 // Discard status replies from before this action.
        toggle.isEnabled = false; disable.isEnabled = false; reconnect.isEnabled = false
        do {
            let session = try AuthorizationSession()
            client.request("toggle", enabled: enable, authorization: session.externalData) { [weak self, session] result in
                // Keep authorization alive until the helper reply/timeout.
                withExtendedLifetime(session) {
                    DispatchQueue.main.async { self?.actionFinished(result) }
                }
            }
        } catch {
            actionFinished(.failure(error))
        }
    }

    private func actionFinished(_ result: Result<[String: String], Error>) {
        if case .failure(let error) = result {
            let alert = NSAlert()
            alert.messageText = "Action not confirmed"
            alert.informativeText = error.localizedDescription
            alert.addButton(withTitle: "OK")
            alert.runModal()
        }
        refreshStatus()
    }

    @objc private func reconnectVPN() {
        requestGeneration += 1
        toggle.isEnabled = false; disable.isEnabled = false; reconnect.isEnabled = false
        client.request("reconnect") { [weak self] result in
            DispatchQueue.main.async { self?.actionFinished(result) }
        }
    }

    @objc private func quitApp() { NSApp.terminate(nil) }
}

let app = NSApplication.shared
let delegate = MenuController()
app.delegate = delegate
app.run()
