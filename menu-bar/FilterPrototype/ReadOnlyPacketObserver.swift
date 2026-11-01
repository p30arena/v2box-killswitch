import Foundation
import NetworkExtension

/// Diagnostic packet observer. It records only interface and direction samples
/// and allows every packet. NEFilterPacketContext has no public flow identity.
final class ReadOnlyPacketObserver: NEFilterPacketProvider {
    private let sampleLock = NSLock()
    private var lastSampleByInterface: [String: TimeInterval] = [:]
    private let sampleInterval: TimeInterval = 1

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        packetHandler = { [weak self] _, interface, direction, packetBytes, packetLength in
            guard let self else { return .allow }
            let name = String(cString: nw_interface_get_name(interface))
            let interfaceIndex = nw_interface_get_index(interface)
            let now = ProcessInfo.processInfo.systemUptime
            let directionName = direction == .outbound ? "outbound" : "inbound"
            let sampleKey = "\(name):\(directionName)"
            self.sampleLock.lock()
            let shouldLog = now - (self.lastSampleByInterface[sampleKey] ?? -.infinity) >= self.sampleInterval
            if shouldLog { self.lastSampleByInterface[sampleKey] = now }
            self.sampleLock.unlock()
            if shouldLog {
                NSLog("packet_observation time=%.3f interface=%@ interface_index=%d direction=%@ packet_length=%d",
                      now, name, interfaceIndex,
                      directionName, packetLength)
            }
            return .allow
        }
        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        sampleLock.lock()
        lastSampleByInterface.removeAll()
        sampleLock.unlock()
        completionHandler()
    }
}
