import AppKit

// Deliberately no shell execution, PF access, networking or privileged IPC.
// This preview must never claim to reflect actual protection on the Mac.
final class PreviewController: NSObject, NSApplicationDelegate {
    private var item: NSStatusItem!
    private var simulatedOn = false
    private let stateItem = NSMenuItem(title: "Actual protection: NOT INSPECTED", action: nil, keyEquivalent: "")
    private let previewState = NSMenuItem(title: "Simulated protection: Off", action: nil, keyEquivalent: "")
    private let toggleItem = NSMenuItem(title: "Simulate Enable…", action: #selector(toggle), keyEquivalent: "")

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.title = "Guard DEMO"
        item.button?.toolTip = "UI preview only — does not inspect or change firewall protection"
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "V2Box Guard — PREVIEW ONLY", action: nil, keyEquivalent: ""))
        menu.addItem(stateItem)
        menu.addItem(previewState)
        menu.addItem(.separator())
        toggleItem.target = self
        menu.addItem(toggleItem)
        let reconnect = NSMenuItem(title: "Reconnect VPN (not available in preview)", action: nil, keyEquivalent: "")
        menu.addItem(reconnect)
        menu.addItem(.separator())
        let about = NSMenuItem(title: "Safety and implementation status…", action: #selector(showStatus), keyEquivalent: "")
        about.target = self
        menu.addItem(about)
        let quit = NSMenuItem(title: "Quit Preview (no firewall change)", action: #selector(quitPreview), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
        item.menu = menu
    }

    @objc private func toggle() {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = simulatedOn ? "Simulate disabling protection?" : "Simulate enabling protection?"
        alert.informativeText = "PREVIEW ONLY. This button changes the demo display, not your firewall. In the finished app, disabling protection will allow direct internet traffic. The privileged helper has not been implemented."
        alert.addButton(withTitle: "Simulate")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        simulatedOn.toggle()
        previewState.title = "Simulated protection: \(simulatedOn ? "On" : "Off")"
        toggleItem.title = simulatedOn ? "Simulate Disable…" : "Simulate Enable…"
        // Keep DEMO visible even when the simulated state is On.
        item.button?.title = simulatedOn ? "Guard DEMO ●" : "Guard DEMO ○"
    }

    @objc private func showStatus() {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Not a working kill switch"
        alert.informativeText = "This is an offline menu-bar UI preview. It does not read or alter PF, launchd, VPN state or system configuration. Actual protection is unknown. Do not use this preview to recover connectivity. A reviewed privileged helper and end-to-end tests are required before operational controls can be enabled."
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    @objc private func quitPreview() { NSApp.terminate(nil) }
}

let app = NSApplication.shared
let controller = PreviewController()
app.delegate = controller
app.run()
