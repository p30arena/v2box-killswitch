import Foundation
import Darwin
import Dispatch

private func runPeerCloseCheck() -> Bool {
    let listener = socket(AF_INET, SOCK_STREAM, 0)
    guard listener >= 0 else { return false }
    defer { close(listener) }
    var noSigPipe: Int32 = 1
    _ = setsockopt(listener, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_addr.s_addr = in_addr_t(INADDR_LOOPBACK).bigEndian
    address.sin_port = 0
    let bound = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
    }
    guard bound == 0, listen(listener, 1) == 0 else { return false }
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    guard getsockname(listener, withUnsafeMutablePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { $0 }
    }, &length) == 0 else { return false }
    let port = UInt16(bigEndian: address.sin_port)
    let reset = DispatchSemaphore(value: 0)
    DispatchQueue.global().async {
        let peer = accept(listener, nil, nil)
        if peer >= 0 {
            _ = setsockopt(peer, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
            var lingerValue = linger(l_onoff: 1, l_linger: 0)
            _ = setsockopt(peer, SOL_SOCKET, SO_LINGER, &lingerValue, socklen_t(MemoryLayout<linger>.size))
            close(peer)
        }
        reset.signal()
    }
    let client = socket(AF_INET, SOCK_STREAM, 0)
    guard client >= 0 else { return false }
    defer { close(client) }
    _ = setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
    var clientAddress = sockaddr_in()
    clientAddress.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    clientAddress.sin_family = sa_family_t(AF_INET)
    clientAddress.sin_addr.s_addr = in_addr_t(INADDR_LOOPBACK).bigEndian
    clientAddress.sin_port = port.bigEndian
    let connected = withUnsafePointer(to: &clientAddress) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(client, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
    }
    guard connected == 0, reset.wait(timeout: .now() + 2) == .success else { return false }
    usleep(50_000)
    var byte: UInt8 = 0x55
    let result = withUnsafePointer(to: &byte) { send(client, $0, 1, 0) }
    return result == -1 && (errno == EPIPE || errno == ECONNRESET)
}

private func runLoopbackAcknowledgmentCheck() -> Bool {
    let listener = socket(AF_INET, SOCK_STREAM, 0)
    guard listener >= 0 else { return false }
    defer { close(listener) }
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_addr.s_addr = in_addr_t(INADDR_LOOPBACK).bigEndian
    guard withUnsafePointer(to: &address, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
    } }) == 0, listen(listener, 1) == 0 else { return false }
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    guard getsockname(listener, withUnsafeMutablePointer(to: &address, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { $0 } }), &length) == 0 else { return false }
    let port = address.sin_port
    let server = DispatchSemaphore(value: 0)
    DispatchQueue.global().async {
        let ready = pollUntilReady(listener, events: Int16(POLLIN),
                                   deadline: ProcessInfo.processInfo.systemUptime + 2)
        let peer = ready ? accept(listener, nil, nil) : -1
        if peer >= 0 {
            var noSigPipe: Int32 = 1
            _ = setsockopt(peer, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
            var byte: UInt8 = 0
            if recv(peer, &byte, 1, 0) == 1 { _ = send(peer, &byte, 1, 0) }
            close(peer)
        }
        server.signal()
    }
    let client = socket(AF_INET, SOCK_STREAM, 0)
    guard client >= 0 else { return false }
    defer { close(client) }
    var noSigPipe: Int32 = 1
    _ = setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
    var target = sockaddr_in()
    target.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    target.sin_family = sa_family_t(AF_INET)
    target.sin_addr.s_addr = in_addr_t(INADDR_LOOPBACK).bigEndian
    target.sin_port = port
    guard withUnsafePointer(to: &target, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        connect(client, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
    } }) == 0 else { return false }
    var sent: UInt8 = 0x5a
    guard send(client, &sent, 1, 0) == 1 else { return false }
    guard pollUntilReady(client, events: Int16(POLLIN),
                         deadline: ProcessInfo.processInfo.systemUptime + 2) else { return false }
    var received: UInt8 = 0
    let acknowledged = recv(client, &received, 1, 0) == 1 && received == sent
    return acknowledged && server.wait(timeout: .now() + 2) == .success
}

private func runHTTPSAcknowledgmentCheck() -> Bool {
    guard let url = URL(string: "https://testserver.host/echo") else { return false }
    let marker = "V2BOX-FlowProbe-\(UUID().uuidString)"
    var request = URLRequest(url: url, timeoutInterval: 5)
    request.httpMethod = "POST"
    request.httpBody = Data(marker.utf8)
    let finished = DispatchSemaphore(value: 0)
    let resultLock = NSLock()
    var succeeded = false
    URLSession.shared.dataTask(with: request) { data, response, error in
        if error == nil, let response = response as? HTTPURLResponse, response.statusCode == 200,
           let data, String(data: data, encoding: .utf8)?.contains(marker) == true {
            resultLock.lock()
            succeeded = true
            resultLock.unlock()
        }
        finished.signal()
    }.resume()
    guard finished.wait(timeout: .now() + 7) == .success else { return false }
    resultLock.lock()
    defer { resultLock.unlock() }
    return succeeded
}

private enum ResolutionResult {
    case resolved(UnsafeMutablePointer<addrinfo>)
    case timedOut
    case failed
}

private func resolveWithTimeout(_ host: String, port: String, family: Int32, socketType: Int32,
                                timeoutSeconds: Double = 3) -> ResolutionResult {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/dscacheutil")
    process.arguments = ["-q", "host", "-a", "name", host]
    let output = Pipe()
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    let exited = DispatchSemaphore(value: 0)
    process.terminationHandler = { _ in exited.signal() }
    do { try process.run() } catch { return .failed }
    if exited.wait(timeout: .now() + timeoutSeconds) != .success {
        _ = kill(process.processIdentifier, SIGKILL)
        process.waitUntilExit()
        return .timedOut
    }
    let text = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    let key = family == AF_INET ? "ip_address:" : "ipv6_address:"
    var resultHead: UnsafeMutablePointer<addrinfo>?
    var resultTail: UnsafeMutablePointer<addrinfo>?
    for line in text.split(separator: "\n") {
        guard line.hasPrefix(key) else { continue }
        let address = line.dropFirst(key.count).trimmingCharacters(in: .whitespaces)
        var hints = addrinfo(ai_flags: AI_NUMERICHOST, ai_family: family, ai_socktype: socketType,
                             ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var addressHead: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(address, port, &hints, &addressHead) == 0, let addressHead else { continue }
        if resultHead == nil {
            resultHead = addressHead
        } else {
            resultTail?.pointee.ai_next = addressHead
        }
        var tail = addressHead
        while let next = tail.pointee.ai_next { tail = next }
        resultTail = tail
    }
    if let resultHead { return .resolved(resultHead) }
    return .failed
}

private func pollUntilReady(_ fd: Int32, events: Int16, deadline: Double) -> Bool {
    while true {
        let remaining = max(0, Int((deadline - ProcessInfo.processInfo.systemUptime) * 1000))
        guard remaining > 0 else { return false }
        var descriptor = pollfd(fd: fd, events: events, revents: 0)
        let result = poll(&descriptor, 1, Int32(min(remaining, Int(Int32.max))))
        if result > 0 { return true }
        if result == 0 { return false }
        if errno != EINTR { return false }
    }
}

private func connectWithTimeout(_ fd: Int32,
                                address: UnsafePointer<sockaddr>,
                                length: socklen_t,
                                timeoutMilliseconds: Int32 = 3000) -> Bool {
    let originalFlags = fcntl(fd, F_GETFL, 0)
    guard originalFlags >= 0,
          fcntl(fd, F_SETFL, originalFlags | O_NONBLOCK) == 0 else { return false }
    defer { _ = fcntl(fd, F_SETFL, originalFlags) }

    if connect(fd, address, length) == 0 { return true }
    guard errno == EINPROGRESS else { return false }
    let deadline = ProcessInfo.processInfo.systemUptime + Double(timeoutMilliseconds) / 1000
    guard pollUntilReady(fd, events: Int16(POLLOUT), deadline: deadline) else { return false }
    var socketError: Int32 = 0
    var optionLength = socklen_t(MemoryLayout<Int32>.size)
    guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &optionLength) == 0 else { return false }
    return socketError == 0
}

private enum ProbeResult {
    case accepted, acknowledged, resolutionFailed, connectFailed, sendFailed, echoTimedOut, echoMismatch
}

private func socketLocalAddress(_ fd: Int32) -> String {
    var storage = sockaddr_storage()
    var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
    let result = withUnsafeMutablePointer(to: &storage) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            getsockname(fd, $0, &length)
        }
    }
    guard result == 0 else { return "unknown" }
    var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
    let nameResult = withUnsafePointer(to: &storage) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            getnameinfo($0, length, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
        }
    }
    return nameResult == 0 ? String(cString: host) : "unknown"
}

private func runSocketProbe(family: Int32, socketType: Int32, host: String,
                            port: String, verifyEcho: Bool = false,
                            connectDatagram: Bool = false) -> ProbeResult {
    var numeric4 = in_addr()
    var numeric6 = in6_addr()
    let isNumeric = host.withCString {
        inet_pton(AF_INET, $0, &numeric4) == 1 || inet_pton(AF_INET6, $0, &numeric6) == 1
    }
    let head: UnsafeMutablePointer<addrinfo>?
    if isNumeric {
        var hints = addrinfo(ai_flags: AI_NUMERICHOST, ai_family: family, ai_socktype: socketType,
                             ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var numericHead: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, port, &hints, &numericHead) == 0 else { return .resolutionFailed }
        head = numericHead
    } else {
        switch resolveWithTimeout(host, port: port, family: family, socketType: socketType) {
        case .resolved(let result): head = result
        case .timedOut: return .resolutionFailed
        case .failed: return .resolutionFailed
        }
    }
    guard let head else { return .resolutionFailed }
    defer { freeaddrinfo(head) }

    var exhaustionResult: ProbeResult = .connectFailed
    var current: UnsafeMutablePointer<addrinfo>? = head
    while let entry = current {
        let info = entry.pointee
        let fd = socket(info.ai_family, info.ai_socktype, info.ai_protocol)
        if fd >= 0 {
            defer { close(fd) }
            var noSigPipe: Int32 = 1
            _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
            if socketType == SOCK_STREAM {
                if connectWithTimeout(fd, address: info.ai_addr, length: info.ai_addrlen) {
                    let marker: [UInt8] = verifyEcho ? Array("V2BOX\n".utf8) : [0x16]
                    let sent = marker.withUnsafeBytes { send(fd, $0.baseAddress!, $0.count, 0) }
                    guard sent == marker.count else { return .sendFailed }
                    print("test_probe local_source=\(socketLocalAddress(fd))")
                    guard verifyEcho else { return .accepted }
                    var echoed = [UInt8](repeating: 0, count: marker.count)
                    let readResult: (Int, Bool) = echoed.withUnsafeMutableBytes { raw in
                        let deadline = ProcessInfo.processInfo.systemUptime + 3
                        var offset = 0
                        while offset < raw.count {
                            guard pollUntilReady(fd, events: Int16(POLLIN), deadline: deadline) else {
                                return (offset, true)
                            }
                            let count = recv(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset, 0)
                            guard count > 0 else { return (offset, false) }
                            offset += count
                        }
                        return (offset, false)
                    }
                    if readResult.1 { return .echoTimedOut }
                    return readResult.0 == marker.count && echoed == marker ? .acknowledged : .echoMismatch
                }
            } else {
                var byte: UInt8 = 0x01
                let sent: Int
                if connectDatagram {
                    guard connect(fd, info.ai_addr, info.ai_addrlen) == 0 else {
                        exhaustionResult = .connectFailed
                        current = info.ai_next
                        continue
                    }
                    sent = withUnsafePointer(to: &byte) { send(fd, $0, 1, 0) }
                } else {
                    sent = withUnsafePointer(to: &byte) {
                        sendto(fd, $0, 1, 0, info.ai_addr, info.ai_addrlen)
                    }
                }
                if sent == 1 {
                    print("test_probe local_source=\(socketLocalAddress(fd))")
                    return .accepted
                }
                exhaustionResult = .sendFailed
            }
        }
        current = info.ai_next
    }
    return exhaustionResult
}

let scenarios: [(String, Int32, Int32)] = [
    ("tcp4", AF_INET, SOCK_STREAM),
    ("tcp6", AF_INET6, SOCK_STREAM),
    ("udp4", AF_INET, SOCK_DGRAM),
    ("udp6", AF_INET6, SOCK_DGRAM)
]
var requested = Set<String>()
var host = "example.com"
var port = "443"
var tcpEchoCheck = false
var peerCloseCheck = false
var resolverDeadlineCheck = false
var echoCheck = false
var httpsEchoCheck = false
var connectedUDPCheck = false
var arguments = Array(CommandLine.arguments.dropFirst())
var explicitHost = false
var explicitPort = false
while !arguments.isEmpty {
    let argument = arguments.removeFirst()
    if argument == "--peer-close-check" {
        peerCloseCheck = true
    } else if argument == "--resolver-deadline-check" {
        resolverDeadlineCheck = true
    } else if argument == "--loopback-ack-check" {
        echoCheck = true
    } else if argument == "--https-echo-check" {
        httpsEchoCheck = true
    } else if argument == "--connected-udp-check" {
        connectedUDPCheck = true
    } else if argument == "--tcp-echo-check" {
        tcpEchoCheck = true
        if !explicitHost { host = "tcpbin.com" }
        if !explicitPort { port = "4242" }
    } else if argument == "--port", !arguments.isEmpty {
        port = arguments.removeFirst()
        explicitPort = true
    } else if argument == "--port" {
        fputs("--port requires a port number\n", stderr); exit(2)
    } else if argument == "--host", !arguments.isEmpty {
        host = arguments.removeFirst()
        explicitHost = true
    } else if argument == "--host" {
        fputs("--host requires a hostname or IP address\n", stderr); exit(2)
    } else if scenarios.contains(where: { $0.0 == argument }) {
        requested.insert(argument)
    } else {
        fputs("Unknown argument: \(argument)\nUsage: FlowProbe [tcp4|tcp6|udp4|udp6 ...] [--host hostname-or-IP] [--port port]\n       FlowProbe --connected-udp-check [udp4|udp6 ...] [--host hostname-or-IP] [--port port]\n", stderr)
        exit(2)
    }
}
let exclusiveModeCount = [peerCloseCheck, resolverDeadlineCheck, echoCheck, httpsEchoCheck, tcpEchoCheck, connectedUDPCheck].filter { $0 }.count
guard exclusiveModeCount <= 1 else { fputs("Choose only one diagnostic mode\n", stderr); exit(2) }
if peerCloseCheck {
    guard requested.isEmpty else {
        fputs("--peer-close-check cannot be combined with network scenarios\n", stderr); exit(2)
    }
    let passed = runPeerCloseCheck()
    print("test_probe peer_close_check=\(passed ? "send_failed_without_signal" : "unexpected_result")")
    exit(passed ? 0 : 1)
}
if resolverDeadlineCheck {
    guard requested.isEmpty else {
        fputs("--resolver-deadline-check cannot be combined with network scenarios\n", stderr); exit(2)
    }
    let started = Date()
    let outcome = resolveWithTimeout("example.com", port: "443", family: AF_INET, socketType: SOCK_STREAM,
                                     timeoutSeconds: 0.001)
    let expired: Bool
    if case .timedOut = outcome { expired = Date().timeIntervalSince(started) < 1 }
    else { expired = false }
    print("test_probe resolver_deadline_check=\(expired ? "timed_out_and_child_terminated" : "resolved_before_deadline")")
    exit(expired ? 0 : 1)
}
if echoCheck {
    guard requested.isEmpty else { fputs("--loopback-ack-check cannot be combined with network scenarios\n", stderr); exit(2) }
    let passed = runLoopbackAcknowledgmentCheck()
    print("test_probe loopback_ack_check=\(passed ? "acknowledged" : "failed")")
    exit(passed ? 0 : 1)
}
if httpsEchoCheck {
    guard requested.isEmpty else { fputs("--https-echo-check cannot be combined with raw socket scenarios\n", stderr); exit(2) }
    let passed = runHTTPSAcknowledgmentCheck()
    print("test_probe https_echo_check=\(passed ? "response_acknowledged" : "failed") delivery_verified=\(passed)")
    exit(passed ? 0 : 1)
}
if tcpEchoCheck {
    guard requested.isEmpty || requested.allSatisfy({ $0 == "tcp4" || $0 == "tcp6" }) else {
        fputs("--tcp-echo-check supports tcp4 and tcp6 only\n", stderr); exit(2)
    }
}
if connectedUDPCheck {
    guard requested.isEmpty || requested.allSatisfy({ $0 == "udp4" || $0 == "udp6" }) else {
        fputs("--connected-udp-check supports udp4 and udp6 only\n", stderr); exit(2)
    }
}
let selected = requested.isEmpty
    ? (tcpEchoCheck ? scenarios.filter { $0.0 == "tcp4" || $0.0 == "tcp6" } :
       (connectedUDPCheck ? scenarios.filter { $0.0 == "udp4" || $0.0 == "udp6" } : scenarios))
    : scenarios.filter { requested.contains($0.0) }
guard !selected.isEmpty else {
    fputs("Usage: FlowProbe [tcp4|tcp6|udp4|udp6 ...] [--host hostname-or-IP] [--port port]\n       FlowProbe --connected-udp-check [udp4|udp6 ...] [--host hostname-or-IP] [--port port]\n", stderr)
    exit(2)
}
var failed = false
for (name, family, type) in selected {
    print("test_probe scenario=\(name) started uptime=\(ProcessInfo.processInfo.systemUptime)")
    if tcpEchoCheck && type != SOCK_STREAM { continue }
    let result = runSocketProbe(family: family, socketType: type, host: host, port: port,
                                verifyEcho: tcpEchoCheck, connectDatagram: connectedUDPCheck)
    let label: String
    switch result {
    case .accepted: label = "local_socket_acceptance_only"
    case .acknowledged: label = "echo_acknowledged"
    case .resolutionFailed: label = "resolution_failed"
    case .connectFailed: label = "connect_failed"
    case .sendFailed: label = "send_failed"
    case .echoTimedOut: label = "echo_timeout"
    case .echoMismatch: label = "echo_mismatch"
    }
    print("test_probe scenario=\(name) result=\(label) delivery_verified=\(result == .acknowledged)")
    failed = failed || !(result == .accepted || result == .acknowledged)
}
exit(failed ? 1 : 0)
