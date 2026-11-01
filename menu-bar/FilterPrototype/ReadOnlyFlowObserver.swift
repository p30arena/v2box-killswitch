import Foundation
import NetworkExtension
import Darwin
import Security

/// Diagnostic Phase 1 observer. It allows ordinary flows and only drops the
/// exact local test probe when its local endpoint remains unresolved.
final class ReadOnlyFlowObserver: NEFilterDataProvider {
    private let identityCacheLock = NSLock()
    private var identityCache: [Data: CachedIdentity] = [:]
    private let identityQueue: OperationQueue = {
        let queue = OperationQueue()
        queue.name = "org.v2boxkillswitch.firewallprobe.identity"
        queue.qualityOfService = .utility
        queue.maxConcurrentOperationCount = 2
        return queue
    }()
    private let identityCacheTTL: TimeInterval = 300
    private let maximumIdentityEntries = 512
    private let maximumPendingIdentityTokens = 256
    private var pendingIdentityTokens: Set<Data> = []
    private var identityWaiters: [Data: [(String) -> Void]] = [:]
    private var identityGeneration: UInt64 = 0
    private let seenFlowLock = NSLock()
    private var seenFlowIdentifiers: [UUID: TimeInterval] = [:]
    private let observationTTL: TimeInterval = 300
    private let maximumTrackedFlows = 4096

    private struct CachedIdentity {
        let value: String
        let expiresAt: TimeInterval
    }

    private func identityClass(_ token: Data?, completion: ((String) -> Void)? = nil) -> String {
        guard let auditToken = token else { return "unknown_no_token" }
        let now = ProcessInfo.processInfo.systemUptime
        identityCacheLock.lock()
        if let cached = identityCache[auditToken], cached.expiresAt > now {
            identityCacheLock.unlock()
            return cached.value
        }
        identityCache.removeValue(forKey: auditToken)
        if pendingIdentityTokens.contains(auditToken) {
            if let completion, (identityWaiters[auditToken]?.count ?? 0) < 128 {
                identityWaiters[auditToken, default: []].append(completion)
            }
            identityCacheLock.unlock()
            return "unknown_identity_pending"
        }
        guard pendingIdentityTokens.count < maximumPendingIdentityTokens else {
            identityCacheLock.unlock()
            return "unknown_identity_queue_full"
        }
        pendingIdentityTokens.insert(auditToken)
        if let completion { identityWaiters[auditToken] = [completion] }
        let generation = identityGeneration
        identityCacheLock.unlock()
        // Never perform code-signature validation on the filter callback queue.
        identityQueue.addOperation { [weak self] in
            guard let self else { return }
            let result = self.resolveIdentityClass(auditToken)
            let expiry = ProcessInfo.processInfo.systemUptime +
                (result.hasPrefix("unknown_") ? 5 : self.identityCacheTTL)
            self.identityCacheLock.lock()
            guard generation == self.identityGeneration else {
                self.identityCacheLock.unlock()
                return
            }
            self.pendingIdentityTokens.remove(auditToken)
            let waiters = self.identityWaiters.removeValue(forKey: auditToken) ?? []
            self.identityCache = self.identityCache.filter { $0.value.expiresAt > ProcessInfo.processInfo.systemUptime }
            if self.identityCache.count >= self.maximumIdentityEntries,
               let oldest = self.identityCache.min(by: { $0.value.expiresAt < $1.value.expiresAt })?.key {
                self.identityCache.removeValue(forKey: oldest)
            }
            self.identityCache[auditToken] = CachedIdentity(value: result, expiresAt: expiry)
            self.identityCacheLock.unlock()
            waiters.forEach { $0(result) }
        }
        return "unknown_identity_pending"
    }

    private func resolveIdentityClass(_ auditToken: Data) -> String {
        guard auditToken.count == MemoryLayout<audit_token_t>.size else { return "unknown_bad_audit_token" }
        var nativeToken = audit_token_t()
        withUnsafeMutableBytes(of: &nativeToken) { destination in
            _ = auditToken.copyBytes(to: destination)
        }
        guard let task = SecTaskCreateWithAuditToken(kCFAllocatorDefault, nativeToken) else {
            return "unknown_audit_task"
        }
        var taskError: Unmanaged<CFError>?
        let taskIdentifier = SecTaskCopySigningIdentifier(task, &taskError) as String?
        let taskTeam = SecTaskCopyValueForEntitlement(
            task, "com.apple.developer.team-identifier" as CFString, nil
        ) as? String
        let reviewedIDs = ["hossin.asaadi.V2Box", "hossin.asaadi.V2Box.PacketTunnel"]
        if let taskIdentifier {
            if taskIdentifier as String == "org.v2boxkillswitch.firewallprobe.testprobe" { return "test_probe" }
            if !reviewedIDs.contains(taskIdentifier as String) {
                if taskTeam == "5AC5438XDR" { return "other_v2box_team" }
                return taskTeam == nil ? "other_no_team_identifier" : "other_team_mismatch"
            }
        }
        var guestCode: SecCode?
        let attributes = [kSecGuestAttributeAudit as String: auditToken] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, SecCSFlags(), &guestCode) == errSecSuccess,
              let guestCode else { return "unknown_guest_code" }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(guestCode, SecCSFlags(), &staticCode) == errSecSuccess,
              let staticCode else { return "unknown_static_code" }
        var signingInfo: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(staticCode, SecCSFlags(), &signingInfo)
        let signingValues = (infoStatus == errSecSuccess ? signingInfo as? [String: Any] : nil)
        guard let identifier = taskIdentifier ?? signingValues?[kSecCodeInfoIdentifier as String] as? String else {
            return "unknown_signing_identifier"
        }
        let teamIdentifier = taskTeam ?? (signingValues?[kSecCodeInfoTeamIdentifier as String] as? String)
        // Diagnostic label only: the local ad-hoc probe identity grants no exemption.
        if identifier == "org.v2boxkillswitch.firewallprobe.testprobe" { return "test_probe" }
        guard reviewedIDs.contains(identifier) else {
            if teamIdentifier == "5AC5438XDR" { return "other_v2box_team" }
            return teamIdentifier == nil ? "other_no_team_identifier" : "other_team_mismatch"
        }
        guard teamIdentifier == "5AC5438XDR" else { return "v2box_identifier_wrong_team" }
        var requirement: SecRequirement?
        let expression = "anchor apple generic and identifier \"" + identifier + "\""
        guard SecRequirementCreateWithString(expression as CFString, SecCSFlags(), &requirement) == errSecSuccess,
              let requirement,
              SecStaticCodeCheckValidity(staticCode, SecCSFlags(), requirement) == errSecSuccess else {
            return "unknown_static_signature"
        }
        return identifier == "hossin.asaadi.V2Box" ? "v2box_app" : "v2box_provider"
    }

    private func hasConcreteLocalAddress(_ flow: NEFilterFlow) -> Bool {
        guard let socket = flow as? NEFilterSocketFlow,
              let endpoint = socket.localEndpoint as? NWHostEndpoint else { return false }
        let candidate = endpoint.hostname
        var address4 = in_addr()
        if candidate.withCString({ inet_pton(AF_INET, $0, &address4) }) == 1 {
            return address4.s_addr != 0
        }
        var address6 = in6_addr()
        if candidate.withCString({ inet_pton(AF_INET6, $0, &address6) }) == 1 {
            return withUnsafeBytes(of: &address6) { bytes in
                let isIPv4Mapped = bytes.count == 16 && bytes[0..<10].allSatisfy { $0 == 0 }
                    && bytes[10] == 0xff && bytes[11] == 0xff
                if isIPv4Mapped { return bytes[12..<16].contains { $0 != 0 } }
                return bytes.contains { $0 != 0 }
            }
        }
        return false
    }

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let outbound = NENetworkRule(remoteNetwork: nil, remotePrefix: 0,
                                    localNetwork: nil, localPrefix: 0,
                                    protocol: .any, direction: .outbound)
        let rule = NEFilterRule(networkRule: outbound, action: .filterData)
        let settings = NEFilterSettings(rules: [rule], defaultAction: .allow)
        apply(settings, completionHandler: completionHandler)
    }

    override func stopFilter(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        seenFlowLock.lock()
        seenFlowIdentifiers.removeAll()
        seenFlowLock.unlock()
        identityQueue.cancelAllOperations()
        identityCacheLock.lock()
        identityGeneration &+= 1
        identityCache.removeAll()
        identityWaiters.removeAll()
        pendingIdentityTokens.removeAll()
        identityCacheLock.unlock()
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        let socket = flow as? NEFilterSocketFlow
        let flowID = flow.identifier.uuidString
        let localFamily: String
        let localAddress: String
        if let host = socket?.localEndpoint as? NWHostEndpoint {
            let candidate = host.hostname
            var address4 = in_addr()
            var address6 = in6_addr()
            if candidate.withCString({ inet_pton(AF_INET, $0, &address4) }) == 1 {
                localFamily = "ipv4"
                localAddress = candidate
            } else if candidate.withCString({ inet_pton(AF_INET6, $0, &address6) }) == 1 {
                localFamily = "ipv6"
                localAddress = candidate
            } else {
                localFamily = "unknown"
                localAddress = "unparsed"
            }
        } else {
            localFamily = "unknown"
            localAddress = "absent"
        }

        // Never log identities, remote endpoints, hostnames, ports, or payloads.
        NSLog("flow_observation phase=new flow_id=%@ time=%.3f source_app=%@ source_process=%@ app_identity=%@ process_identity=%@ local_endpoint=%@ local_family=%@ local_address=%@",
              flowID,
              ProcessInfo.processInfo.systemUptime,
              identityClass(flow.sourceAppAuditToken, completion: { resolved in
                  NSLog("flow_observation phase=identity_resolved flow_id=%@ source=app identity=%@", flowID, resolved)
              }),
              identityClass(flow.sourceProcessAuditToken, completion: { resolved in
                  NSLog("flow_observation phase=identity_resolved flow_id=%@ source=process identity=%@", flowID, resolved)
              }),
              flow.sourceAppAuditToken == nil ? "absent" : "present",
              flow.sourceProcessAuditToken == nil ? "absent" : "present",
              socket?.localEndpoint == nil ? "absent" : "present",
              localFamily, localAddress)
        return .filterDataVerdict(withFilterInbound: false, peekInboundBytes: 0,
                                  filterOutbound: true, peekOutboundBytes: 1)
    }

    override func handleOutboundData(from flow: NEFilterFlow,
                                     readBytesStartOffset: Int,
                                     readBytes: Data) -> NEFilterDataVerdict {
        guard let flowID = flow.identifier as UUID? else { return .allow() }
        let flowIDString = flowID.uuidString
        let appClass = identityClass(flow.sourceAppAuditToken)
        let processClass = identityClass(flow.sourceProcessAuditToken)
        seenFlowLock.lock()
        let now = ProcessInfo.processInfo.systemUptime
        seenFlowIdentifiers = seenFlowIdentifiers.filter { now - $0.value < observationTTL }
        let firstObservation = seenFlowIdentifiers[flowID] == nil
        if firstObservation {
            if seenFlowIdentifiers.count >= maximumTrackedFlows,
               let oldest = seenFlowIdentifiers.min(by: { $0.value < $1.value })?.key {
                seenFlowIdentifiers.removeValue(forKey: oldest)
            }
            seenFlowIdentifiers[flowID] = now
        }
        seenFlowLock.unlock()
        if firstObservation, let socket = flow as? NEFilterSocketFlow {
            let endpoint = socket.localEndpoint as? NWHostEndpoint
            NSLog("flow_observation phase=outbound flow_id=%@ time=%.3f source_app=%@ source_process=%@ local_endpoint=%@ local_address=%@",
                  flowID.uuidString,
                  ProcessInfo.processInfo.systemUptime,
                  appClass,
                  processClass,
                  endpoint == nil ? "absent" : "present",
                  endpoint?.hostname ?? "absent")
        }
        if appClass == "unknown_identity_pending" || processClass == "unknown_identity_pending" {
            let lock = NSLock()
            var remaining = Set<Data>()
            var resolvedClasses: [String] = []
            if appClass == "unknown_identity_pending", let token = flow.sourceAppAuditToken { remaining.insert(token) }
            if processClass == "unknown_identity_pending", let token = flow.sourceProcessAuditToken { remaining.insert(token) }
            guard !remaining.isEmpty, remaining.count <= 2 else { return .allow() }
            for token in remaining {
                let finish: (String) -> Void = { [weak self, weak flow] value in
                    guard let self, let flow else { return }
                    lock.lock()
                    resolvedClasses.append(value)
                    remaining.remove(token)
                    let finished = remaining.isEmpty
                    let shouldDrop = finished && resolvedClasses.contains("test_probe") && !self.hasConcreteLocalAddress(flow)
                    lock.unlock()
                    guard finished else { return }
                    if shouldDrop {
                        NSLog("flow_observation phase=probe_endpoint_unresolved_drop flow_id=%@", flowIDString)
                    }
                    self.resumeFlow(flow, with: shouldDrop ? NEFilterDataVerdict.drop() : NEFilterDataVerdict.allow())
                    NSLog("flow_observation phase=identity_resumed flow_id=%@ dropped=%@", flowIDString, shouldDrop ? "true" : "false")
                }
                let current = identityClass(token, completion: finish)
                if current != "unknown_identity_pending" { finish(current) }
            }
            return .pause()
        }
        if appClass == "test_probe" || processClass == "test_probe" {
            guard hasConcreteLocalAddress(flow) else {
                NSLog("flow_observation phase=probe_endpoint_unresolved_drop flow_id=%@", flowID.uuidString)
                return .drop()
            }
        }
        return .allow()
    }

    override func handleOutboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        seenFlowLock.lock()
        seenFlowIdentifiers.removeValue(forKey: flow.identifier)
        seenFlowLock.unlock()
        return .allow()
    }
}
