import AppKit
import CoreFoundation
import Darwin
import Network
import SwiftUI
import SystemConfiguration
import dnssd
import os

// MARK: - Constants

let clashBundleID = "io.github.clash-verge-rev.clash-verge-rev"
let claudeBundleID = "com.anthropic.claudefordesktop"
let blockedRegions: Set<String> = ["CN", "HK", "MO", "RU"]
let sgKeywords = ["新加坡", "SG", "Singapore", "狮城"]
let logFile = NSString(string: "~/ClaudeGuard/guard.log").expandingTildeInPath

// MARK: - Low-level Concurrency & Time Helpers

final class OnceFlag: @unchecked Sendable {
    private let state = OSAllocatedUnfairLock(initialState: false)
    func tryFire() -> Bool {
        state.withLock { fired in
            if fired { return false }
            fired = true
            return true
        }
    }
}

func currentHHMMSS() -> String {
    var now = time(nil)
    var tmVal = tm()
    localtime_r(&now, &tmVal)
    return String(format: "%02d:%02d:%02d", tmVal.tm_hour, tmVal.tm_min, tmVal.tm_sec)
}

func rotateLogIfNeeded(path: String, maxBytes: Int = 1_048_576, keepBytes: Int = 524_288) {
    guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
          let size = (attrs[.size] as? NSNumber)?.intValue, size > maxBytes,
          let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return }
    let tailStart = max(0, data.count - keepBytes)
    var slice = data[tailStart...]
    if let nl = slice.firstIndex(of: UInt8(ascii: "\n")), nl + 1 < slice.endIndex {
        slice = slice[(nl + 1)...]
    }
    try? Data(slice).write(to: URL(fileURLWithPath: path), options: .atomic)
}

// MARK: - Native POSIX Poll & Unix Socket HTTP Client (Zero Subprocesses)

private enum PollWaitResult { case ready, timedOut, failed }

private func waitPoll(fd: Int32, events: Int16, deadline: TimeInterval) -> PollWaitResult {
    while true {
        let remaining = deadline - ProcessInfo.processInfo.systemUptime
        if remaining <= 0 { return .timedOut }
        let ms = Int32(min(Double(Int32.max), max(1.0, ceil(remaining * 1000.0))))
        var pfd = pollfd(fd: fd, events: events, revents: 0)
        let rc = Darwin.poll(&pfd, 1, ms)
        if rc > 0 {
            if (pfd.revents & Int16(POLLNVAL)) != 0 { return .failed }
            return .ready
        }
        if rc == 0 { return .timedOut }
        if errno == EINTR { continue }
        return .failed
    }
}

struct UnixHTTPResult {
    let body: String?
    let timedOut: Bool
}

private func decodeChunkedBody(_ data: Data) -> Data? {
    var out = Data()
    var idx = data.startIndex
    let crlf = Data("\r\n".utf8)
    while idx < data.endIndex {
        guard let lineEnd = data.range(of: crlf, in: idx..<data.endIndex),
              let sizeHeader = String(data: data[idx..<lineEnd.lowerBound], encoding: .ascii) else { return nil }
        let hexPart = sizeHeader.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false).first?
            .trimmingCharacters(in: .whitespaces) ?? ""
        guard let chunkLen = Int(hexPart, radix: 16), chunkLen >= 0 else { return nil }
        let chunkStart = lineEnd.upperBound
        if chunkLen == 0 {
            guard data.distance(from: chunkStart, to: data.endIndex) >= 2 else { return nil }
            return out
        }
        guard data.distance(from: chunkStart, to: data.endIndex) >= chunkLen + 2 else { return nil }
        let chunkEnd = data.index(chunkStart, offsetBy: chunkLen)
        guard data[chunkEnd] == UInt8(ascii: "\r"),
              data[data.index(after: chunkEnd)] == UInt8(ascii: "\n") else { return nil }
        out.append(data[chunkStart..<chunkEnd])
        idx = data.index(chunkEnd, offsetBy: 2)
    }
    return nil
}

private func parseHTTPResponse(_ raw: Data) -> String? {
    let crlfSep = Data("\r\n\r\n".utf8)
    let lfSep = Data("\n\n".utf8)
    let headerEnd: Data.Index
    let bodyStart: Data.Index
    if let r = raw.range(of: crlfSep) {
        headerEnd = r.lowerBound
        bodyStart = r.upperBound
    } else if let r = raw.range(of: lfSep) {
        headerEnd = r.lowerBound
        bodyStart = r.upperBound
    } else {
        return nil
    }
    guard let headerStr = String(data: raw[..<headerEnd], encoding: .utf8)
            ?? String(data: raw[..<headerEnd], encoding: .isoLatin1) else { return nil }
    let lines = headerStr.split(whereSeparator: \.isNewline)
    guard let statusLine = lines.first else { return nil }
    let parts = statusLine.split(whereSeparator: \.isWhitespace)
    guard parts.count >= 2, parts[0].hasPrefix("HTTP/"),
          let code = Int(parts[1]), (200...299).contains(code) else { return nil }
    if code == 204 || code == 304 { return "" }

    var contentLength: Int?
    var isChunked = false
    for line in lines.dropFirst() {
        if let colon = line.firstIndex(of: ":") {
            let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let val = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            if name == "content-length" {
                contentLength = Int(val)
            } else if name == "transfer-encoding", val.lowercased().contains("chunked") {
                isChunked = true
            }
        }
    }
    let bodySlice = raw[bodyStart...]
    if isChunked {
        guard let decoded = decodeChunkedBody(Data(bodySlice)) else { return nil }
        return String(data: decoded, encoding: .utf8)
    }
    var bodyData = bodySlice
    if let cl = contentLength, cl >= 0 {
        if bodyData.count < cl { return nil }
        bodyData = bodyData.prefix(cl)
    }
    return String(data: Data(bodyData), encoding: .utf8)
}

func unixHTTPRequest(socketPath: String, path: String, method: String,
                     body: String?, timeout: TimeInterval, maxResponseBytes: Int = 4_194_304) -> UnixHTTPResult {
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let maxPath = MemoryLayout.size(ofValue: addr.sun_path)
    let pathBytes = Array(socketPath.utf8)
    guard !pathBytes.isEmpty, pathBytes.count < maxPath else {
        return UnixHTTPResult(body: nil, timedOut: false)
    }
    addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    withUnsafeMutableBytes(of: &addr.sun_path) { raw in
        raw.initializeMemory(as: UInt8.self, repeating: 0)
        for (i, b) in pathBytes.enumerated() { raw[i] = b }
    }

    let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return UnixHTTPResult(body: nil, timedOut: false) }
    defer { Darwin.close(fd) }

    var one: Int32 = 1
    _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
    let flags = fcntl(fd, F_GETFL, 0)
    if flags >= 0 { _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK) }

    let deadline = ProcessInfo.processInfo.systemUptime + max(0.05, timeout)
    let connectRC = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    if connectRC != 0 {
        if errno == EINPROGRESS || errno == EINTR {
            switch waitPoll(fd: fd, events: Int16(POLLOUT), deadline: deadline) {
            case .ready:
                var soErr: Int32 = 0
                var len = socklen_t(MemoryLayout<Int32>.size)
                if getsockopt(fd, SOL_SOCKET, SO_ERROR, &soErr, &len) != 0 || soErr != 0 {
                    return UnixHTTPResult(body: nil, timedOut: false)
                }
            case .timedOut:
                return UnixHTTPResult(body: nil, timedOut: true)
            case .failed:
                return UnixHTTPResult(body: nil, timedOut: false)
            }
        } else {
            return UnixHTTPResult(body: nil, timedOut: false)
        }
    }

    let bodyBytes = body.map { Array($0.utf8) }
    var header = "\(method) \(path) HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n"
    if let bodyBytes {
        header += "Content-Type: application/json\r\nContent-Length: \(bodyBytes.count)\r\n"
    }
    header += "\r\n"
    var requestBytes = Array(header.utf8)
    if let bodyBytes { requestBytes.append(contentsOf: bodyBytes) }

    var sent = 0
    while sent < requestBytes.count {
        let n = requestBytes.withUnsafeBytes { raw in
            Darwin.send(fd, raw.baseAddress!.advanced(by: sent), requestBytes.count - sent, 0)
        }
        if n > 0 {
            sent += n
        } else if n < 0 && errno == EINTR {
            continue
        } else if n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
            switch waitPoll(fd: fd, events: Int16(POLLOUT), deadline: deadline) {
            case .ready: continue
            case .timedOut: return UnixHTTPResult(body: nil, timedOut: true)
            case .failed: return UnixHTTPResult(body: nil, timedOut: false)
            }
        } else {
            return UnixHTTPResult(body: nil, timedOut: false)
        }
    }

    var response = Data()
    var chunk = [UInt8](repeating: 0, count: 16_384)
    let crlfSep = Data("\r\n\r\n".utf8)
    let chunkEndMarker = Data("0\r\n\r\n".utf8)
    var headersParsed = false
    var bodyStartOffset = 0
    var isChunked = false
    var expectedTotalBytes: Int?

    while response.count < maxResponseBytes {
        let n = chunk.withUnsafeMutableBytes { raw in
            Darwin.recv(fd, raw.baseAddress!, raw.count, 0)
        }
        if n > 0 {
            response.append(contentsOf: chunk[..<n])
            if !headersParsed, let r = response.range(of: crlfSep),
               let hdr = String(data: response[..<r.lowerBound], encoding: .isoLatin1) {
                headersParsed = true
                bodyStartOffset = response.distance(from: response.startIndex, to: r.upperBound)
                let lines = hdr.split(whereSeparator: \.isNewline)
                if let first = lines.first {
                    let parts = first.split(whereSeparator: \.isWhitespace)
                    if parts.count >= 2, let code = Int(parts[1]), (code == 204 || code == 304) {
                        expectedTotalBytes = bodyStartOffset
                    }
                }
                if expectedTotalBytes == nil {
                    for line in lines.dropFirst() {
                        guard let colon = line.firstIndex(of: ":") else { continue }
                        let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
                        let val = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                        if name == "transfer-encoding", val.lowercased().contains("chunked") {
                            isChunked = true
                            break
                        } else if name == "content-length", let cl = Int(val), cl >= 0 {
                            expectedTotalBytes = bodyStartOffset + cl
                        }
                    }
                }
            }
            if let expectedTotalBytes, response.count >= expectedTotalBytes { break }
            if isChunked, response.count >= bodyStartOffset + 5,
               response.suffix(5) == chunkEndMarker,
               decodeChunkedBody(Data(response.dropFirst(bodyStartOffset))) != nil {
                break
            }
        } else if n == 0 {
            break
        } else if errno == EINTR {
            continue
        } else if errno == EAGAIN || errno == EWOULDBLOCK {
            switch waitPoll(fd: fd, events: Int16(POLLIN), deadline: deadline) {
            case .ready: continue
            case .timedOut: return UnixHTTPResult(body: nil, timedOut: true)
            case .failed: return UnixHTTPResult(body: nil, timedOut: false)
            }
        } else {
            return UnixHTTPResult(body: nil, timedOut: false)
        }
    }

    guard let parsed = parseHTTPResponse(response) else {
        return UnixHTTPResult(body: nil, timedOut: false)
    }
    return UnixHTTPResult(body: parsed, timedOut: false)
}

// 新版 Verge 使用当前用户的 service socket，旧版路径只作兼容回退。
// 先验证 /configs，避免把无效文件或其他服务误认成代理内核。
final class CoreClient: @unchecked Sendable {
    let candidates: [String]
    let requestTimeout: TimeInterval
    private let socketLock = OSAllocatedUnfairLock<String?>(initialState: nil)

    var socket: String? {
        get { socketLock.withLock { $0 } }
        set { socketLock.withLock { $0 = newValue } }
    }

    init(candidates: [String] = [
        "/var/run/clash-verge-service/users/\(getuid())/verge-mihomo.sock",
        "/tmp/verge/verge-mihomo.sock"
    ], requestTimeout: TimeInterval = 2.0) {
        self.candidates = candidates
        self.requestTimeout = requestTimeout
    }

    func callWithStatus(_ path: String, method: String = "GET", body: String? = nil,
                        timeout: TimeInterval? = nil) -> UnixHTTPResult {
        let limit = timeout ?? requestTimeout
        if let cached = socket {
            let res = unixHTTPRequest(socketPath: cached, path: path, method: method, body: body, timeout: limit)
            if res.body != nil { return res }
            socket = nil
            // 写操作可能已被处理，不能因响应丢失而重复执行或写到另一个内核。
            if method != "GET" { return UnixHTTPResult(body: "", timedOut: res.timedOut) }
            for candidate in candidates where candidate != cached {
                if let fallback = probeAndCall(candidate: candidate, path: path, method: method, body: body, timeout: limit) {
                    return fallback
                }
            }
            return UnixHTTPResult(body: nil, timedOut: res.timedOut)
        }

        var anyTimedOut = false
        for candidate in candidates {
            let attrs = try? FileManager.default.attributesOfItem(atPath: candidate)
            guard attrs?[.type] as? FileAttributeType == .typeSocket else { continue }
            let cfgRes = unixHTTPRequest(socketPath: candidate, path: "/configs", method: "GET", body: nil, timeout: limit)
            if cfgRes.timedOut { anyTimedOut = true; continue }
            guard let config = cfgRes.body,
                  let tun = parseJSON(config)?["tun"] as? [String: Any],
                  tun["enable"] is Bool else { continue }
            socket = candidate
            if path == "/configs" && method == "GET" {
                return UnixHTTPResult(body: config, timedOut: false)
            }
            return unixHTTPRequest(socketPath: candidate, path: path, method: method, body: body, timeout: limit)
        }
        return UnixHTTPResult(body: nil, timedOut: anyTimedOut)
    }

    private func probeAndCall(candidate: String, path: String, method: String,
                              body: String?, timeout: TimeInterval) -> UnixHTTPResult? {
        let attrs = try? FileManager.default.attributesOfItem(atPath: candidate)
        guard attrs?[.type] as? FileAttributeType == .typeSocket else { return nil }
        let cfgRes = unixHTTPRequest(socketPath: candidate, path: "/configs", method: "GET", body: nil, timeout: timeout)
        guard let config = cfgRes.body,
              let tun = parseJSON(config)?["tun"] as? [String: Any],
              tun["enable"] is Bool else { return nil }
        socket = candidate
        if path == "/configs" && method == "GET" {
            return UnixHTTPResult(body: config, timedOut: false)
        }
        return unixHTTPRequest(socketPath: candidate, path: path, method: method, body: body, timeout: timeout)
    }

    func call(_ path: String, method: String = "GET", body: String? = nil) -> String {
        callWithStatus(path, method: method, body: body).body ?? ""
    }
}

let coreClient = CoreClient()

func coreAPI(_ path: String, method: String = "GET", body: String? = nil) -> String {
    coreClient.call(path, method: method, body: body)
}

func parseJSON(_ s: String) -> [String: Any]? {
    guard !s.isEmpty, let d = s.data(using: .utf8) else { return nil }
    return (try? JSONSerialization.jsonObject(with: d)) as? [String: Any]
}

func pctEncode(_ s: String) -> String {
    s.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? s
}

// MARK: - Native Kernel Route, DNS (mDNSResponder IPC), and Network Signature

// 通过 UDP connect() 触发内核路由表同步选路（零网络发包、零子进程），定位实际出站网卡。
func routeInterface(for literalIP: String) -> String? {
    var v4 = in_addr()
    var v6 = in6_addr()
    let family: Int32
    if inet_pton(AF_INET, literalIP, &v4) == 1 {
        family = AF_INET
    } else if inet_pton(AF_INET6, literalIP, &v6) == 1 {
        family = AF_INET6
    } else {
        return nil
    }

    let fd = Darwin.socket(family, SOCK_DGRAM, IPPROTO_UDP)
    guard fd >= 0 else { return nil }
    defer { Darwin.close(fd) }

    let connected: Int32
    if family == AF_INET {
        var dst = sockaddr_in()
        dst.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        dst.sin_family = sa_family_t(AF_INET)
        dst.sin_port = UInt16(443).bigEndian
        dst.sin_addr = v4
        connected = withUnsafePointer(to: &dst) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
    } else {
        var dst = sockaddr_in6()
        dst.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        dst.sin6_family = sa_family_t(AF_INET6)
        dst.sin6_port = UInt16(443).bigEndian
        dst.sin6_addr = v6
        connected = withUnsafePointer(to: &dst) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
    }
    guard connected == 0 else { return nil }

    var local = sockaddr_storage()
    var localLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
    let gotName = withUnsafeMutablePointer(to: &local) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.getsockname(fd, $0, &localLen)
        }
    }
    guard gotName == 0 else { return nil }

    if family == AF_INET6 {
        let scopeID = withUnsafePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_scope_id }
        }
        if scopeID != 0 {
            var nameBuf = [CChar](repeating: 0, count: Int(IFNAMSIZ))
            if if_indextoname(scopeID, &nameBuf) != nil {
                return String(cString: nameBuf)
            }
        }
    }

    var ifap: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifap) == 0, let first = ifap else { return nil }
    defer { freeifaddrs(first) }

    var cur: UnsafeMutablePointer<ifaddrs>? = first
    while let ifa = cur?.pointee {
        defer { cur = ifa.ifa_next }
        let flags = Int32(ifa.ifa_flags)
        guard let addr = ifa.ifa_addr, Int32(addr.pointee.sa_family) == family,
              (flags & IFF_UP) != 0, (flags & IFF_RUNNING) != 0 else { continue }
        if family == AF_INET {
            let a = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr }
            let b = withUnsafePointer(to: &local) {
                $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr }
            }
            if a == b && a != 0 { return String(cString: ifa.ifa_name) }
        } else {
            let a = addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
            let b = withUnsafePointer(to: &local) {
                $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
            }
            if withUnsafeBytes(of: a, { ab in withUnsafeBytes(of: b, { bb in ab.elementsEqual(bb) }) }) {
                return String(cString: ifa.ifa_name)
            }
        }
    }
    return nil
}

func ipv6RouteInterface() -> String? {
    routeInterface(for: "2606:4700:4700::1111")
}

func ipv4RouteInterface() -> String? {
    routeInterface(for: "1.1.1.1")
}

func tunnelRouteInterfaces() -> (v6: String?, v4: String?, combined: String?) {
    let v6 = ipv6RouteInterface()
    guard let v6, v6.hasPrefix("utun") else { return (v6, nil, v6) }
    let v4 = ipv4RouteInterface()
    guard let v4, v4.hasPrefix("utun") else { return (v6, v4, v4) }
    if v4 != v6 { return (v6, v4, "\(v6)/\(v4)") }
    return (v6, v4, v6)
}

func tunnelRouteInterface() -> String? {
    tunnelRouteInterfaces().combined
}

private final class DNSCallbackState {
    var ipv4: String?
    var transientFailure = false
    var finished = false
}

// 直连 mDNSResponder Unix IPC 并以 poll() 限流超时，不拉起 dscacheutil 子进程、不泄漏阻塞线程。
func lookupIPv4(_ host: String, timeout: TimeInterval = 1.5) -> (ip: String?, timedOut: Bool) {
    let state = DNSCallbackState()
    return withExtendedLifetime(state) {
        var sdRef: DNSServiceRef?
        let ctx = Unmanaged.passUnretained(state).toOpaque()
        let callback: DNSServiceGetAddrInfoReply = { _, flags, _, errorCode, _, address, _, context in
            guard let context else { return }
            let state = Unmanaged<DNSCallbackState>.fromOpaque(context).takeUnretainedValue()
            if errorCode == kDNSServiceErr_NoError,
               let address, Int32(address.pointee.sa_family) == AF_INET {
                var addr = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if state.ipv4 == nil, inet_ntop(AF_INET, &addr, &buf, socklen_t(buf.count)) != nil {
                    state.ipv4 = String(cString: buf)
                    state.finished = true
                    return
                }
            }
            if errorCode == kDNSServiceErr_Timeout || errorCode == kDNSServiceErr_ServiceNotRunning {
                state.transientFailure = true
            }
            if errorCode != kDNSServiceErr_NoError || (flags & DNSServiceFlags(kDNSServiceFlagsMoreComing)) == 0 {
                state.finished = true
            }
        }
        let err = DNSServiceGetAddrInfo(&sdRef, 0, 0, DNSServiceProtocol(kDNSServiceProtocol_IPv4), host, callback, ctx)
        guard err == kDNSServiceErr_NoError, let ref = sdRef else {
            return (nil, err == kDNSServiceErr_ServiceNotRunning || err == kDNSServiceErr_Timeout)
        }
        defer { DNSServiceRefDeallocate(ref) }

        let fd = DNSServiceRefSockFD(ref)
        guard fd >= 0 else { return (nil, false) }
        let deadline = ProcessInfo.processInfo.systemUptime + max(0.05, timeout)
        while !state.finished {
            switch waitPoll(fd: fd, events: Int16(POLLIN), deadline: deadline) {
            case .ready:
                let procErr = DNSServiceProcessResult(ref)
                if procErr != kDNSServiceErr_NoError {
                    return (state.ipv4, state.ipv4 == nil && (procErr == kDNSServiceErr_ServiceNotRunning || procErr == kDNSServiceErr_Timeout))
                }
            case .timedOut:
                return (nil, true)
            case .failed:
                return (nil, false)
            }
        }
        return (state.ipv4, state.ipv4 == nil && state.transientFailure)
    }
}

private let dynamicStoreLock = OSAllocatedUnfairLock()
private let sharedDynamicStore: SCDynamicStore? = SCDynamicStoreCreate(nil, "com.claudeguard" as CFString, nil, nil)

func globalNetworkStoreSnapshot() -> (dnsServers: [String], routerSig: String) {
    let dnsKey = "State:/Network/Global/DNS" as CFString
    let v4Key = "State:/Network/Global/IPv4" as CFString
    let multi: [String: Any]? = dynamicStoreLock.withLock {
        guard let store = sharedDynamicStore else { return nil }
        return SCDynamicStoreCopyMultiple(store, [dnsKey, v4Key] as CFArray, nil) as? [String: Any]
    }
    let dnsDict = (multi?[dnsKey as String] as? [String: Any])
        ?? (SCDynamicStoreCopyValue(nil, dnsKey) as? [String: Any])
    let v4Dict = (multi?[v4Key as String] as? [String: Any])
        ?? (SCDynamicStoreCopyValue(nil, v4Key) as? [String: Any])
    let servers = dnsDict?["ServerAddresses"] as? [String] ?? []
    let routerSig: String
    if let v4Dict {
        let iface = v4Dict["PrimaryInterface"] as? String ?? ""
        let service = v4Dict["PrimaryService"] as? String ?? ""
        let router = v4Dict["Router"] as? String ?? ""
        routerSig = "\(iface)|\(service)|\(router)"
    } else {
        routerSig = "none"
    }
    return (servers, routerSig)
}

func systemDNSServers() -> [String] {
    globalNetworkStoreSnapshot().dnsServers
}

// 仅采集真实物理网卡 (en*) 与隧道网卡 (utun*) 的有效地址，忽略 Simulator bridge/vmenet、AirDrop awdl/llw 及临时 IPv6 轮换噪声。
func relevantInterfaceAddressesSignature() -> String {
    var ifap: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifap) == 0, let first = ifap else { return "" }
    defer { freeifaddrs(first) }

    var entries: [String] = []
    var cur: UnsafeMutablePointer<ifaddrs>? = first
    while let ifa = cur?.pointee {
        defer { cur = ifa.ifa_next }
        let flags = Int32(ifa.ifa_flags)
        guard (flags & IFF_UP) != 0, (flags & IFF_RUNNING) != 0, (flags & IFF_LOOPBACK) == 0,
              let addr = ifa.ifa_addr else { continue }
        let name = String(cString: ifa.ifa_name)
        let isPhysical = name.hasPrefix("en")
        let isTun = name.hasPrefix("utun")
        guard isPhysical || isTun else { continue }

        let family = Int32(addr.pointee.sa_family)
        if family == AF_INET {
            var a = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
            var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            if inet_ntop(AF_INET, &a, &buf, socklen_t(buf.count)) != nil {
                let ip = String(cString: buf)
                if !ip.hasPrefix("169.254.") { entries.append("\(name)=\(ip)") }
            }
        } else if family == AF_INET6 && isTun {
            var a = addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
            var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            if inet_ntop(AF_INET6, &a, &buf, socklen_t(buf.count)) != nil {
                let ip = String(cString: buf)
                if !ip.lowercased().hasPrefix("fe80:") { entries.append("\(name)=\(ip)") }
            }
        }
    }
    return entries.sorted().joined(separator: ",")
}

func resolveActiveNodeInfo(config: [String: Any]?, proxiesRoot: [String: Any]?) -> (display: String, signature: String) {
    let mode = (config?["mode"] as? String)?.lowercased() ?? ""
    if mode == "direct" { return ("直连", "direct") }
    let proxies = proxiesRoot?["proxies"] as? [String: [String: Any]] ?? [:]
    let entryGroup: String = {
        if mode == "global" { return "GLOBAL" }
        if proxies["PROXY"] != nil { return "PROXY" }
        let selectors = proxies.keys.sorted().filter { key in
            key != "GLOBAL" && (proxies[key]?["type"] as? String) == "Selector"
        }
        return selectors.first { $0.contains("手动") }
            ?? selectors.first { $0.contains("节点") }
            ?? selectors.first { $0.contains("漏网") }
            ?? selectors.first
            ?? "GLOBAL"
    }()
    var chain: [String] = []
    var cur = entryGroup
    var visited = Set<String>()
    while !cur.isEmpty, !visited.contains(cur), let item = proxies[cur], let now = item["now"] as? String, !now.isEmpty {
        visited.insert(cur)
        chain.append(now)
        cur = now
    }
    if chain.isEmpty {
        let fallback = mode == "rule" ? "规则分流" : (mode.isEmpty ? "—" : mode)
        return (fallback, "\(mode)|")
    }
    let display = chain.count >= 2 ? "\(chain[0]) → \(chain.last!)" : chain[0]
    return (display, "\(mode)|\(entryGroup)->" + chain.joined(separator: "->"))
}

func shouldIgnorePathEvent(wake: Bool, gateFailure: String?, lastPass: Bool,
                           newSignature: String, lastSignature: String, inFlightSignature: String?) -> Bool {
    guard !wake, gateFailure == nil, !newSignature.isEmpty else { return false }
    if lastPass && newSignature == lastSignature { return true }
    if let inFlightSignature, !inFlightSignature.isEmpty, newSignature == inFlightSignature { return true }
    return false
}

// MARK: - Remote Probes (Native Network.framework & Ephemeral URLSession)

// STUN Binding Request，读取 UDP 路径的 IPv4 出口。
func probeSTUN(host: String, port: NWEndpoint.Port, timeout: TimeInterval = 2.2) -> String? {
    let magic: [UInt8] = [0x21, 0x12, 0xa4, 0x42]
    let transaction = (0..<12).map { _ in UInt8.random(in: .min ... .max) }
    let request = Data([0x00, 0x01, 0x00, 0x00] + magic + transaction)

    let parameters = NWParameters.udp
    (parameters.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options)?.version = .v4
    let connection = NWConnection(host: NWEndpoint.Host(host), port: port, using: parameters)
    let response = OSAllocatedUnfairLock<Data?>(initialState: nil)
    let done = DispatchSemaphore(value: 0)
    let once = OnceFlag()
    let finish = { if once.tryFire() { done.signal() } }

    connection.stateUpdateHandler = { state in
        if case .failed = state { finish() }
        if case .cancelled = state { finish() }
    }
    connection.start(queue: .global(qos: .utility))
    defer { connection.cancel() }
    connection.send(content: request, completion: .contentProcessed { error in
        guard error == nil else { finish(); return }
        connection.receiveMessage { data, _, _, _ in
            response.withLock { $0 = data }
            finish()
        }
    })

    guard done.wait(timeout: .now() + timeout) == .success,
          let data = response.withLock({ $0 }) else { return nil }
    let bytes = Array(data)
    guard bytes.count >= 20, bytes[0] == 0x01, bytes[1] == 0x01,
          bytes[4..<8].elementsEqual(magic),
          bytes[8..<20].elementsEqual(transaction) else { return nil }

    let end = 20 + Int(bytes[2]) * 256 + Int(bytes[3])
    guard end <= bytes.count else { return nil }
    var offset = 20
    while offset + 4 <= end {
        let type = Int(bytes[offset]) * 256 + Int(bytes[offset + 1])
        let length = Int(bytes[offset + 2]) * 256 + Int(bytes[offset + 3])
        let value = offset + 4
        guard value + length <= end else { return nil }
        if (type == 0x0020 || type == 0x0001), length >= 8, bytes[value + 1] == 0x01 {
            return (0..<4).map { index in
                let octet = bytes[value + 4 + index]
                return String(type == 0x0020 ? octet ^ magic[index] : octet)
            }.joined(separator: ".")
        }
        offset = value + (length + 3) / 4 * 4
    }
    return nil
}

func probeSTUNConcurrent(timeout: TimeInterval = 2.2) -> String {
    let servers: [(String, NWEndpoint.Port)] = [
        ("stun.l.google.com", 19302),
        ("stun.cloudflare.com", 3478)
    ]
    let winner = OSAllocatedUnfairLock<String?>(initialState: nil)
    let done = DispatchSemaphore(value: 0)
    let remaining = OSAllocatedUnfairLock(initialState: servers.count)
    let once = OnceFlag()

    for (host, port) in servers {
        DispatchQueue.global(qos: .utility).async {
            if let ip = probeSTUN(host: host, port: port, timeout: timeout), !ip.isEmpty {
                let firstWin = winner.withLock { cur -> Bool in
                    if cur == nil { cur = ip; return true }
                    return false
                }
                if firstWin, once.tryFire() { done.signal() }
            }
            let left = remaining.withLock { count -> Int in
                count -= 1
                return count
            }
            if left == 0, once.tryFire() { done.signal() }
        }
    }
    _ = done.wait(timeout: .now() + timeout + 0.3)
    return winner.withLock { $0 } ?? ""
}

// 强制走真实公网 IPv6 字面量发起 TLS 探测，绕开 macOS 将 Fake-IPv4 映射为 ::ffff:198.18.x.x 的假阳性。
func probeIPv6CloudflareTrace(timeout: TimeInterval = 4.5) -> (loc: String, ip: String)? {
    let tls = NWProtocolTLS.Options()
    sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, "www.cloudflare.com")
    let tcp = NWProtocolTCP.Options()
    let params = NWParameters(tls: tls, tcp: tcp)
    (params.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options)?.version = .v6

    let conn = NWConnection(host: NWEndpoint.Host("2606:4700:4700::1111"), port: 443, using: params)
    let buffer = OSAllocatedUnfairLock(initialState: Data())
    let done = DispatchSemaphore(value: 0)
    let once = OnceFlag()
    let finish = { if once.tryFire() { done.signal() } }

    conn.stateUpdateHandler = { state in
        switch state {
        case .ready:
            let req = Data("GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nUser-Agent: ClaudeGuard/2.0\r\nConnection: close\r\n\r\n".utf8)
            conn.send(content: req, completion: .contentProcessed { err in
                guard err == nil else { finish(); return }
                func receiveLoop() {
                    conn.receive(minimumIncompleteLength: 1, maximumLength: 8192) { data, _, isComplete, recvErr in
                        var enough = false
                        if let data, !data.isEmpty {
                            enough = buffer.withLock { buf in
                                buf.append(data)
                                return buf.count >= 16_384
                            }
                        }
                        if isComplete || recvErr != nil || enough {
                            finish()
                        } else {
                            receiveLoop()
                        }
                    }
                }
                receiveLoop()
            })
        case .failed, .cancelled:
            finish()
        default:
            break
        }
    }
    conn.start(queue: .global(qos: .utility))
    defer { conn.cancel() }

    guard done.wait(timeout: .now() + timeout) == .success else { return nil }
    let raw = String(decoding: buffer.withLock { $0 }, as: UTF8.self)
    return parseCloudflareTrace(raw)
}

func probeIPv6CloudflareResilient(
    isLocalTunnelIntact: () -> Bool = { verifiedLocalTunnelGateFailure() == nil },
    performAttempt: () -> (loc: String, ip: String)? = { probeIPv6CloudflareTrace(timeout: 4.5) }
) -> (loc: String, ip: String)? {
    if let first = performAttempt() {
        return first
    }
    guard isLocalTunnelIntact() else { return nil }
    return performAttempt()
}

func parseCloudflareTrace(_ raw: String) -> (loc: String, ip: String)? {
    let body: Substring
    if let r = raw.range(of: "\r\n\r\n") {
        let head = raw[..<r.lowerBound]
        if head.hasPrefix("HTTP/"), !head.contains(" 200 ") { return nil }
        body = raw[r.upperBound...]
    } else {
        body = raw[...]
    }
    var loc = "", ip = ""
    for lineSub in body.split(whereSeparator: \.isNewline) {
        let line = lineSub.trimmingCharacters(in: .whitespacesAndNewlines)
        if line.hasPrefix("loc=") { loc = String(line.dropFirst(4)) }
        if line.hasPrefix("ip=") { ip = String(line.dropFirst(3)) }
    }
    return loc.isEmpty ? nil : (loc, ip)
}

func makeDirectURLSession() -> URLSession {
    let cfg = URLSessionConfiguration.ephemeral
    cfg.connectionProxyDictionary = [:]
    cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
    cfg.urlCache = nil
    cfg.httpCookieAcceptPolicy = .never
    cfg.httpShouldSetCookies = false
    cfg.timeoutIntervalForRequest = 6
    cfg.timeoutIntervalForResource = 7
    cfg.httpAdditionalHeaders = ["User-Agent": "ClaudeGuard/2.0"]
    return URLSession(configuration: cfg)
}

struct HTTPProbeResult {
    let statusCode: Int
    let body: String
}

func httpFetchResult(session: URLSession, url urlString: String, method: String = "GET",
                     body: Data? = nil, headers: [String: String] = [:], timeout: TimeInterval = 6) -> HTTPProbeResult {
    guard let url = URL(string: urlString) else { return HTTPProbeResult(statusCode: 0, body: "") }
    var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: timeout)
    req.httpMethod = method
    req.httpBody = body
    for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }

    let done = DispatchSemaphore(value: 0)
    let once = OnceFlag()
    let box = OSAllocatedUnfairLock(initialState: HTTPProbeResult(statusCode: 0, body: ""))
    let task = session.dataTask(with: req) { data, response, error in
        if error == nil {
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            let decoded = data.map { String(decoding: $0, as: UTF8.self) } ?? ""
            box.withLock { $0 = HTTPProbeResult(statusCode: code, body: decoded) }
        }
        if once.tryFire() { done.signal() }
    }
    task.resume()
    if done.wait(timeout: .now() + timeout + 0.5) == .timedOut {
        task.cancel()
        return HTTPProbeResult(statusCode: 0, body: "")
    }
    return box.withLock { $0 }
}

func httpFetch(session: URLSession, url urlString: String, method: String = "GET",
               body: Data? = nil, headers: [String: String] = [:], timeout: TimeInterval = 6) -> String {
    httpFetchResult(session: session, url: urlString, method: method, body: body, headers: headers, timeout: timeout).body
}

func sanitizeCountryCode(_ raw: String) -> String? {
    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
    guard trimmed.count == 2, trimmed.allSatisfy({ $0.isASCII && $0.isLetter }) else { return nil }
    return trimmed
}

enum AnthropicProbeDisposition { case allowed, rejected, transientFailure }

func classifyAnthropicResponse(_ result: HTTPProbeResult) -> AnthropicProbeDisposition {
    if result.body.contains("authentication_error") {
        return .allowed
    }
    if result.statusCode == 403
        || result.body.contains("Request not allowed")
        || result.body.contains("\"forbidden\"") {
        return .rejected
    }
    if result.statusCode == 0 || result.statusCode == 408 || result.statusCode == 429 || result.statusCode >= 500 {
        return .transientFailure
    }
    return result.body.isEmpty ? .transientFailure : .rejected
}

func probeAnthropicResilient(
    maxTransientRetries: Int = 2,
    isLocalTunnelIntact: () -> Bool = { verifiedLocalTunnelGateFailure() == nil },
    performAttempt: (Int) -> HTTPProbeResult
) -> Bool {
    for attempt in 0...max(0, maxTransientRetries) {
        switch classifyAnthropicResponse(performAttempt(attempt)) {
        case .allowed:
            return true
        case .rejected:
            return false
        case .transientFailure:
            guard attempt < maxTransientRetries, isLocalTunnelIntact() else { return false }
        }
    }
    return false
}

func probeAnthropicLive(primarySession: URLSession) -> Bool {
    probeAnthropicResilient { attempt in
        if attempt == 0 {
            return httpFetchResult(
                session: primarySession,
                url: "https://api.anthropic.com/v1/messages",
                method: "POST",
                body: Data("{}".utf8),
                headers: ["content-type": "application/json"],
                timeout: 6.5
            )
        }
        let fresh = makeDirectURLSession()
        defer { fresh.finishTasksAndInvalidate() }
        return httpFetchResult(
            session: fresh,
            url: "https://api.anthropic.com/v1/messages",
            method: "POST",
            body: Data("{}".utf8),
            headers: ["content-type": "application/json", "Connection": "close"],
            timeout: 6.5
        )
    }
}

// MARK: - Local Gate & Process Protection

func resolveRealClaudeAppPath(homeDir: String = NSHomeDirectory(),
                              installedPath: String = "/Applications/Claude.app",
                              registeredPath: () -> String? = {
                                  NSWorkspace.shared.urlForApplication(withBundleIdentifier: claudeBundleID)?.path
                              }) -> String? {
    func isRealApp(_ path: String) -> Bool {
        let url = URL(fileURLWithPath: path).appendingPathComponent("Contents/Info.plist")
        guard let data = try? Data(contentsOf: url),
              let info = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any]
        else { return false }
        return info["ClaudeGuardShim"] as? Bool != true && info["CFBundleIdentifier"] as? String != "com.claudeguard.shim"
    }
    let hidden = "\(homeDir)/Library/ClaudeGuard/Claude.app"
    if isRealApp(hidden) { return hidden }
    if isRealApp(installedPath) { return installedPath }
    return registeredPath().flatMap { isRealApp($0) ? $0 : nil }
}

private func firstField(_ key: String, in output: String) -> String? {
    for line in output.split(separator: "\n") {
        let fields = line.split(whereSeparator: \.isWhitespace)
        if fields.first == Substring(key) { return fields.dropFirst().first.map(String.init) }
    }
    return nil
}

func localTunnelGateFailure(
    readConfig: () -> [String: Any]? = { parseJSON(coreClient.callWithStatus("/configs", timeout: 1.5).body ?? "") },
    routeInterface: () -> String? = tunnelRouteInterface,
    dnsLookup: () -> String = { lookupIPv4("claude.ai", timeout: 1.5).ip.map { "ip_address: \($0)" } ?? "" }
) -> String? {
    guard let cfg = readConfig(),
          let tun = cfg["tun"] as? [String: Any],
          let enabled = tun["enable"] as? Bool
    else { return "代理内核接口不可达，TUN 状态未知" }
    guard enabled else { return "TUN 已关闭" }
    if (cfg["mode"] as? String)?.lowercased() == "direct" {
        return "代理处于直连模式，未走隧道"
    }
    guard let addresses = tun["inet6-address"] as? [String], !addresses.isEmpty else {
        return "TUN 未接管 IPv6 路由"
    }
    let expectedDevice = (tun["device"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let rIf = routeInterface() ?? ""
    let routeOK = rIf.hasPrefix("utun") && !rIf.contains("/") && (expectedDevice.isEmpty || rIf == expectedDevice)
    guard routeOK else { return "TUN 未接管 IPv6 路由" }
    guard firstField("ip_address:", in: dnsLookup())?.hasPrefix("198.18.") == true
    else { return "TUN 已开但系统 DNS 未被 Fake-IP 接管" }
    return nil
}

// 区分“真实失守”与“高内存压力下用户态进程短暂换页超时”：
// 1) 内核路由未进 utun、TUN 关闭、直连模式、DNS 返回非 Fake-IP —— 零重试立即判定失守；
// 2) 仅当内核 IPv4/IPv6 路由确认仍在 utun 内且发生 poll 超时时，立即复核一次，消除模拟器高负载下的误杀。
func verifiedLocalTunnelGateFailure(
    fetchConfig: (TimeInterval) -> (config: [String: Any]?, timedOut: Bool) = { timeout in
        let res = coreClient.callWithStatus("/configs", timeout: timeout)
        return (res.body.flatMap(parseJSON), res.timedOut)
    },
    checkRoute: () -> String? = tunnelRouteInterface,
    resolveDNS: (TimeInterval) -> (ip: String?, timedOut: Bool) = { timeout in
        lookupIPv4("claude.ai", timeout: timeout)
    }
) -> String? {
    var cfgAttempt = fetchConfig(1.5)
    if cfgAttempt.config == nil && cfgAttempt.timedOut,
       let r = checkRoute(), r.hasPrefix("utun"), !r.contains("/") {
        cfgAttempt = fetchConfig(2.0)
    }
    return localTunnelGateFailure(
        readConfig: { cfgAttempt.config },
        routeInterface: checkRoute,
        dnsLookup: {
            var dns = resolveDNS(1.5)
            if dns.ip == nil && dns.timedOut,
               let r = checkRoute(), r.hasPrefix("utun"), !r.contains("/") {
                dns = resolveDNS(2.0)
            }
            return dns.ip.map { "ip_address: \($0)" } ?? ""
        }
    )
}

struct LocalTunnelSnapshot {
    let failure: String?
    let config: [String: Any]?
    let v4Interface: String?
    let v6Interface: String?
}

// 单次心跳复用同一份 /configs 与内核选路快照，避免每 5 秒重复请求 socket 与路由表。
func evaluateVerifiedLocalTunnelGateWithConfig() -> LocalTunnelSnapshot {
    var capturedConfig: [String: Any]?
    var latestRoutes: (v6: String?, v4: String?, combined: String?) = (nil, nil, nil)
    var routesLoaded = false
    let readRoutes: () -> String? = {
        latestRoutes = tunnelRouteInterfaces()
        routesLoaded = true
        return latestRoutes.combined
    }
    let failure = verifiedLocalTunnelGateFailure(
        fetchConfig: { timeout in
            let res = coreClient.callWithStatus("/configs", timeout: timeout)
            let parsed = res.body.flatMap(parseJSON)
            if let parsed { capturedConfig = parsed }
            return (parsed, res.timedOut)
        },
        checkRoute: readRoutes,
        resolveDNS: { timeout in
            lookupIPv4("claude.ai", timeout: timeout)
        }
    )
    if !routesLoaded { _ = readRoutes() }
    return LocalTunnelSnapshot(
        failure: failure,
        config: capturedConfig,
        v4Interface: latestRoutes.v4 ?? ipv4RouteInterface(),
        v6Interface: latestRoutes.v6 ?? ipv6RouteInterface()
    )
}

func fetchCoreJSONResilient(_ path: String, timeout: TimeInterval = 1.5, retryTimeout: TimeInterval = 2.0) -> [String: Any]? {
    var res = coreClient.callWithStatus(path, timeout: timeout)
    if res.body == nil && res.timedOut,
       let r = tunnelRouteInterface(), r.hasPrefix("utun"), !r.contains("/") {
        res = coreClient.callWithStatus(path, timeout: retryTimeout)
    }
    return res.body.flatMap(parseJSON)
}

// 启动与每次全检的第一步；未确认退出时不进入修复和公网探测。
func checkLocalProtection(tunnelFailure: () -> String?, readVersion: () -> String?,
                          cutIfRunning: (String) -> Bool, repair: () -> Void)
    -> (version: String?, failure: String?, canProbe: Bool, stopped: Bool) {
    var failure = tunnelFailure()
    if let failure, !cutIfRunning(failure) { return (nil, failure, false, false) }
    let version = readVersion()
    if version == nil && !cutIfRunning("代理内核接口不可达") { return (nil, failure, false, false) }
    if failure != nil && version != nil {
        repair()
        failure = tunnelFailure()
        if let failure, !cutIfRunning(failure) { return (version, failure, false, false) }
    }
    return (version, failure, failure == nil && version != nil, true)
}

func performOnMain(_ action: @escaping () -> Void) {
    if Thread.isMainThread { action() } else { DispatchQueue.main.async(execute: action) }
}

func isManagedClaudeExecutablePath(_ path: String, homeDir: String = NSHomeDirectory(),
                                   appContentsRoots: [String]? = nil) -> Bool {
    guard path.hasPrefix("/"), !path.hasSuffix("/"), !path.contains("/../"), !path.hasSuffix("/.."),
          !path.contains("/./"), !path.hasSuffix("/."), !path.hasSuffix("/Contents/MacOS/ClaudeShim"),
          !path.contains("ClaudeGuard.app/") else { return false }
    let roots = appContentsRoots ?? ["/Applications/Claude.app/Contents/",
                                     "\(homeDir)/Library/ClaudeGuard/Claude.app/Contents/"]
    if roots.contains(where: { !$0.isEmpty && path.hasPrefix($0.hasSuffix("/") ? $0 : $0 + "/") }) {
        return true
    }
    let shipIt = "com.anthropic.claudefordesktop.ShipIt"
    if let bundle = path.range(of: "/Claude.app/Contents/") {
        let parent = path[..<bundle.lowerBound]
        let cache = "\(homeDir)/Library/Caches/\(shipIt)"
        if parent == cache || parent.hasPrefix(cache + "/") { return true }
        if appContentsRoots == nil, parent.hasPrefix("/var/folders/") || parent.hasPrefix("/private/var/folders/"),
           parent.split(separator: "/").contains(where: { $0.hasPrefix(shipIt + ".") && $0.count > shipIt.count + 1 }) {
            return true
        }
    }
    let versions = "\(homeDir)/.local/share/claude/versions/"
    if path.hasPrefix(versions) {
        let name = path.dropFirst(versions.count)
        return !name.isEmpty && !name.hasPrefix(".") && !name.contains("/")
    }
    guard URL(fileURLWithPath: path).lastPathComponent == "claude" else { return false }
    if path.hasPrefix("\(homeDir)/Library/Application Support/Claude/claude-code/") { return true }
    return appContentsRoots == nil && (path.hasPrefix("/opt/homebrew/Caskroom/claude-code/") ||
                                       path.hasPrefix("/usr/local/Caskroom/claude-code/"))
}

private func isManagedClaudePID(_ pid: pid_t, currentUID: uid_t, selfPID: pid_t,
                                homeDir: String, appContentsRoots: [String]?,
                                onIncompleteScan: () -> Void) -> Bool {
    guard pid > 1, pid != selfPID else { return false }
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout.size(ofValue: info))
    guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size,
          info.pbi_uid == currentUID, info.pbi_status != 5 else { return false }
    var path = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
    guard proc_pidpath(pid, &path, UInt32(path.count)) > 0 else {
        if errno != ESRCH && errno != ENOENT { onIncompleteScan() }
        return false
    }
    return isManagedClaudeExecutablePath(String(cString: path), homeDir: homeDir, appContentsRoots: appContentsRoots)
}

func listManagedClaudePIDs(currentUID: uid_t = getuid(), selfPID: pid_t = getpid(),
                           homeDir: String = NSHomeDirectory(), appContentsRoots: [String]? = nil,
                           onIncompleteScan: () -> Void = {}) -> [pid_t] {
    let type = UInt32(PROC_ALL_PIDS)
    let stride = MemoryLayout<pid_t>.stride
    let estimate = proc_listpids(type, 0, nil, 0)
    guard estimate > 0 else { onIncompleteScan(); return [] }
    var count = Int(estimate) / stride + 64
    while count <= Int(Int32.max) / stride {
        var buffer = [pid_t](repeating: 0, count: count)
        let capacity = Int32(count * stride)
        let bytes = proc_listpids(type, 0, &buffer, capacity)
        guard bytes > 0 else { break }
        if bytes < capacity - Int32(stride) {
            let matches = buffer.prefix(Int(bytes) / stride).filter {
                isManagedClaudePID($0, currentUID: currentUID, selfPID: selfPID, homeDir: homeDir,
                                   appContentsRoots: appContentsRoots, onIncompleteScan: onIncompleteScan)
            }
            return Set(matches).sorted()
        }
        count *= 2
    }
    onIncompleteScan()
    return []
}

@discardableResult
func terminateManagedClaude(
    gracePeriod: TimeInterval, timeout: TimeInterval,
    listPIDs: () -> [pid_t], hasRunningApp: () -> Bool = { false },
    requestAppTerminate: () -> Void = {}, forceAppTerminate: () -> Void = {},
    sendSignal: (pid_t, Int32) -> Void = { pid, sig in _ = Darwin.kill(pid, sig) }
) -> Bool {
    let start = ProcessInfo.processInfo.systemUptime
    let graceEnd = start + gracePeriod
    let deadline = start + max(timeout, gracePeriod + 0.1)
    var pids = listPIDs()
    let appAlive = hasRunningApp()
    if pids.isEmpty && !appAlive { return true }
    if appAlive { requestAppTerminate() }
    for pid in pids { sendSignal(pid, SIGTERM) }

    var forced = false
    while true {
        pids = listPIDs()
        if !hasRunningApp() && pids.isEmpty { return true }
        let now = ProcessInfo.processInfo.systemUptime
        if now >= graceEnd {
            if !forced {
                forceAppTerminate()
                forced = true
            }
            for pid in pids { sendSignal(pid, SIGKILL) }
            if now >= deadline { return false }
        }
        Thread.sleep(forTimeInterval: min(0.05, max(0.005, (forced ? deadline : graceEnd) - now)))
    }
}

func probeSystemFingerprint() -> (ok: Bool, detail: String) {
    NSTimeZone.resetSystemTimeZone()
    let tz: String = {
        if let dest = try? FileManager.default.destinationOfSymbolicLink(atPath: "/etc/localtime"),
           let r = dest.range(of: "zoneinfo/") {
            return String(dest[r.upperBound...])
        }
        return TimeZone.current.identifier
    }()
    let cnTZ: Set<String> = ["Asia/Shanghai", "Asia/Urumqi", "Asia/Chongqing", "Asia/Harbin", "PRC"]
    let langs = CFPreferencesCopyValue(
        "AppleLanguages" as CFString,
        kCFPreferencesAnyApplication,
        kCFPreferencesCurrentUser,
        kCFPreferencesAnyHost
    ) as? [String]
    let firstLang = langs?.first ?? Locale.preferredLanguages.first ?? ""
    if cnTZ.contains(tz) {
        return (false, "时区 \(tz) 属中国时区")
    }
    if firstLang.lowercased().hasPrefix("zh") {
        return (false, "首选语言 \(firstLang)（建议改英文）")
    }
    return (true, "时区 \(tz) · \(firstLang)")
}

// 前门脚本与命令行复用的无界面完整硬闸门检查（零子进程，公网探针并发执行）。
func runHeadlessGateCheck() -> (ok: Bool, summary: String) {
    if let localFail = verifiedLocalTunnelGateFailure() {
        return (false, localFail)
    }
    let session = makeDirectURLSession()
    defer { session.finishTasksAndInvalidate() }

    let group = DispatchGroup()
    let stateLock = NSLock()
    var cfTrace: (loc: String, ip: String)?
    var info2Result: [String: Any]?
    var v6Trace: (loc: String, ip: String)?
    var stunIP = ""
    var apiOK = false

    group.enter()
    DispatchQueue.global(qos: .userInitiated).async {
        defer { group.leave() }
        let raw = httpFetch(session: session, url: "https://www.cloudflare.com/cdn-cgi/trace", timeout: 6)
        let parsed = parseCloudflareTrace(raw)
        stateLock.lock(); cfTrace = parsed; stateLock.unlock()
    }

    group.enter()
    DispatchQueue.global(qos: .userInitiated).async {
        defer { group.leave() }
        let info = parseJSON(httpFetch(session: session, url: "https://ipinfo.io/json", timeout: 6))
        stateLock.lock(); info2Result = info; stateLock.unlock()
    }

    group.enter()
    DispatchQueue.global(qos: .userInitiated).async {
        defer { group.leave() }
        let res = probeIPv6CloudflareResilient()
        stateLock.lock(); v6Trace = res; stateLock.unlock()
    }

    group.enter()
    DispatchQueue.global(qos: .userInitiated).async {
        defer { group.leave() }
        let ip = probeSTUNConcurrent(timeout: 2.2)
        stateLock.lock(); stunIP = ip; stateLock.unlock()
    }

    group.enter()
    DispatchQueue.global(qos: .userInitiated).async {
        defer { group.leave() }
        let ok = probeAnthropicLive(primarySession: session)
        stateLock.lock(); apiOK = ok; stateLock.unlock()
    }

    group.wait()

    let egress: (loc: String, ip: String)? = {
        if let cfTrace { return cfTrace }
        if let c = info2Result?["country"] as? String, !c.isEmpty {
            return (c, info2Result?["ip"] as? String ?? "")
        }
        return nil
    }()
    guard let cf = egress else { return (false, "无法获取出口信息") }
    if blockedRegions.contains(cf.loc) { return (false, "出口 \(cf.loc) 属受限地区") }
    if let c2 = info2Result?["country"] as? String, !c2.isEmpty, blockedRegions.contains(c2) {
        return (false, "复核出口 \(c2) 属受限地区")
    }

    guard let v6If = ipv6RouteInterface(), v6If.hasPrefix("utun") else {
        return (false, "IPv6 路由未进入 TUN")
    }
    guard let v6 = v6Trace else { return (false, "真实 IPv6 探测超时或状态未知，拒绝盲放行") }
    if blockedRegions.contains(v6.loc) { return (false, "IPv6 泄漏至受限地区 \(v6.loc)") }

    if !stunIP.isEmpty && stunIP != cf.ip {
        let rawCountry = httpFetch(session: session, url: "https://ipinfo.io/\(stunIP)/country", timeout: 5)
        if let sc = sanitizeCountryCode(rawCountry), blockedRegions.contains(sc) {
            return (false, "UDP 泄漏真实 IP \(stunIP)（\(sc)）")
        }
    }

    guard apiOK else { return (false, "Anthropic 未放行（可能被地区拦截）") }
    if let postFail = verifiedLocalTunnelGateFailure() {
        return (false, postFail)
    }
    return (true, "出口 \(cf.loc) · \(cf.ip)，TUN 开，API 放行")
}

// app 内部发通知：系统自动用 app 图标，点击自动激活 app 并弹面板
// （旧版用 osascript 发→通知归属 Script Editor，图标错、点击跳脚本编辑器 transcript）
func notifyUser(_ msg: String) {
    DispatchQueue.main.async {
        let n = NSUserNotification()
        n.title = "ClaudeGuard"
        n.informativeText = msg
        n.soundName = NSUserNotificationDefaultSoundName
        NSUserNotificationCenter.default.deliver(n)
    }
}

// MARK: - Model

enum CheckState { case pending, running, ok, warn, fail }

struct CheckItem: Identifiable {
    let id: String
    let title: String
    var state: CheckState = .pending
    var detail: String = ""
}

enum Overall { case checking, pass, fail, direct }

private struct GuardRuntimeState {
    var monitoring: Bool = true
    var directMode: Bool = false
    var changingMode: Bool = false
    var busy: Bool = false
    var tickInFlight: Bool = false
    var repairActive: Bool = false
    var lastGuardPass: Bool = false
    var hasFailedSinceStart: Bool = false
    var failureNotified: Bool = false
    var networkGeneration: UInt64 = 0
    var verifiedSignature: String = ""
    var inFlightSignature: String = ""
    var lastNodeDisplay: String = "—"
    var lastNodeSignature: String = ""

    var eventGuardActive: Bool { monitoring && !directMode && !changingMode }
}

final class GuardModel: ObservableObject {
    @Published var overall: Overall = .checking
    @Published var checks: [CheckItem] = []
    @Published var egressInfo: String = "—"
    @Published var monitoring: Bool = true {
        didSet {
            guard monitoring != oldValue else { return }
            let isDirect = runtime.withLock { state -> Bool in
                state.monitoring = monitoring
                return state.directMode
            }
            logLine(monitoring ? "实时守护已开启" : "实时守护已关闭")
            if monitoring && !isDirect {
                nextFullCheckAt = .distantPast
                runFullCheck(autofix: false, openAfter: false, silentIfPass: false)
            }
        }
    }
    @Published var directMode: Bool = false
    @Published var currentNode: String = "—"
    @Published var busy: Bool = false
    @Published var busyText: String = ""
    @Published var lastCheckAt: String = "—"

    var onStatusChange: ((Overall) -> Void)?

    private let runtime = OSAllocatedUnfairLock(initialState: GuardRuntimeState())
    private var savedClashMode: String = "rule"
    private var timer: Timer?
    private var nextAutoRecoveryAt = Date.distantPast
    private var nextFullCheckAt = Date.distantPast
    private let q = DispatchQueue(label: "guard.work", qos: .utility, autoreleaseFrequency: .workItem)
    private let pathMonitor = NWPathMonitor()
    private let pathQueue = DispatchQueue(label: "guard.netpath", qos: .userInitiated, autoreleaseFrequency: .workItem)
    private var receivedInitialPath = false
    private var pathDebounce: DispatchWorkItem?
    private var pendingWake = false
    private var pendingPath = false
    private var pendingManualCheck: (autofix: Bool, openAfter: Bool)?
    private var sleepObservers: [NSObjectProtocol] = []
    private let logLock = NSLock()
    private var logWriteCounter = 0

    // 写回 Verge 自己的配置文件，避免它的界面/重启状态与内核漂移
    private let tunEnablePatch = "{\"ipv6\":true,\"tun\":{\"enable\":true,\"stack\":\"mixed\",\"auto-route\":true,\"strict-route\":true,\"auto-detect-interface\":true,\"dns-hijack\":[\"any:53\",\"tcp://any:53\"],\"inet4-address\":[\"198.18.0.1/30\"],\"inet6-address\":[\"fdfe:dcba:9876::1/126\"]}}"

    private let checkTemplate: [CheckItem] = [
        CheckItem(id: "claudeApp", title: "Claude 应用"),
        CheckItem(id: "clashApp", title: "Clash Verge 应用"),
        CheckItem(id: "core", title: "Clash 内核接口"),
        CheckItem(id: "tun", title: "TUN 模式"),
        CheckItem(id: "egress", title: "出口 · Cloudflare"),
        CheckItem(id: "egress2", title: "出口复核 · ipinfo"),
        CheckItem(id: "v6", title: "IPv6 泄漏"),
        CheckItem(id: "stun", title: "WebRTC/UDP 泄漏"),
        CheckItem(id: "api", title: "Anthropic 放行"),
        CheckItem(id: "fingerprint", title: "指纹 · 时区/语言"),
    ]

    func start() {
        rotateLogIfNeeded(path: logFile)
        checks = checkTemplate
        let center = NSWorkspace.shared.notificationCenter
        sleepObservers.append(center.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) {
            [weak self] _ in
            guard let self else { return }
            let active = self.runtime.withLock { state -> Bool in
                guard state.eventGuardActive else { return false }
                state.networkGeneration &+= 1
                state.inFlightSignature = ""
                return true
            }
            guard active, self.hasRunningClaude() else { return }
            let stopped = self.cutClaudeAndWait(gracePeriod: 0.3, timeout: 2.0)
            self.logLine(stopped ? "系统即将休眠，已预先退出 Claude 防唤醒抢跑" : "系统即将休眠，未能确认 Claude 已退出")
        })
        sleepObservers.append(center.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) {
            [weak self] _ in
            guard let self, self.runtime.withLock({ $0.eventGuardActive }) else { return }
            self.pathQueue.async { self.checkNetworkEvent(wake: true) }
        })
        pathMonitor.pathUpdateHandler = { [weak self] _ in
            guard let self else { return }
            guard self.receivedInitialPath else { self.receivedInitialPath = true; return }
            self.checkNetworkEvent(wake: false)
        }
        pathMonitor.start(queue: pathQueue)
        runFullCheck(autofix: false, openAfter: false, silentIfPass: false)
        let t = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            self?.guardTick()
        }
        t.tolerance = 0.8
        timer = t
    }

    deinit {
        pathMonitor.cancel()
        for observer in sleepObservers { NSWorkspace.shared.notificationCenter.removeObserver(observer) }
    }

    private func computeNetworkSignature(config: [String: Any]? = nil,
                                         proxies: [String: Any]? = nil,
                                         v4If: String? = nil,
                                         v6If: String? = nil) -> String {
        let cfg = config ?? fetchCoreJSONResilient("/configs")
        let mode = (cfg?["mode"] as? String)?.lowercased() ?? ""
        let prx = (mode == "direct") ? nil : (proxies ?? fetchCoreJSONResilient("/proxies"))

        let nodeInfo: (display: String, signature: String)
        if mode != "direct" && prx == nil {
            let cached = runtime.withLock { ($0.lastNodeDisplay, $0.lastNodeSignature) }
            if !cached.1.isEmpty {
                nodeInfo = cached
            } else {
                nodeInfo = resolveActiveNodeInfo(config: cfg, proxiesRoot: nil)
            }
        } else {
            nodeInfo = resolveActiveNodeInfo(config: cfg, proxiesRoot: prx)
        }

        let shouldPublishNode = runtime.withLock { state -> Bool in
            if prx != nil || mode == "direct" {
                state.lastNodeSignature = nodeInfo.signature
            }
            guard state.lastNodeDisplay != nodeInfo.display else { return false }
            state.lastNodeDisplay = nodeInfo.display
            return true
        }
        if shouldPublishNode {
            let display = nodeInfo.display
            DispatchQueue.main.async {
                if self.currentNode != display { self.currentNode = display }
            }
        }

        let resolvedV4 = v4If ?? ipv4RouteInterface() ?? "none"
        let resolvedV6 = v6If ?? ipv6RouteInterface() ?? "none"
        let storeSnap = globalNetworkStoreSnapshot()
        let dns = storeSnap.dnsServers.joined(separator: ",")
        let addrs = relevantInterfaceAddressesSignature()
        return "\(resolvedV4)|\(resolvedV6)|\(storeSnap.routerSig)|\(dns)|\(addrs)|\(nodeInfo.signature)"
    }

    // 专用队列无锁依赖主线程地做毫秒级进程内隧道检查：
    // 1) 失守时立即通过内核信号掐断 Claude（即便 AppKit 主线程正因换页或休眠短暂阻塞也不耽误）；
    // 2) 通过且真实网络/隧道/节点签名未变（如模拟器虚拟网桥或 AirDrop 抖动）时直接静默忽略。
    private func checkNetworkEvent(wake: Bool) {
        let initial = runtime.withLock {
            (active: $0.eventGuardActive, pass: $0.lastGuardPass, repairing: $0.repairActive)
        }
        guard initial.active else { return }

        let snap = evaluateVerifiedLocalTunnelGateWithConfig()
        if let failure = snap.failure {
            if runtime.withLock({ $0.eventGuardActive }), hasRunningClaude() {
                let stopped = cutClaudeAndWait(gracePeriod: 0.3, timeout: 3.5)
                let event = wake ? "系统唤醒" : "网络路径变更"
                let status = stopped ? "已即时断开 Claude" : "未能确认 Claude 已退出"
                logLine("\(event)且隧道失守，\(status)（\(failure)）")
                notifyUser("⚠️ \(failure)，\(status)")
                runtime.withLock { $0.failureNotified = true }
            }
            let shouldSchedule = runtime.withLock { state -> Bool in
                guard state.eventGuardActive, !state.repairActive else { return false }
                state.networkGeneration &+= 1
                state.lastGuardPass = false
                state.hasFailedSinceStart = true
                state.inFlightSignature = ""
                return true
            }
            guard shouldSchedule else { return }
            setOverall(.fail)
            DispatchQueue.main.async { [self] in
                guard self.runtime.withLock({ $0.eventGuardActive }) else { return }
                self.scheduleEventRecheck(wake: wake, observedSignature: "")
            }
            return
        }

        if initial.repairing || runtime.withLock({ $0.repairActive }) { return }
        let newSig = computeNetworkSignature(
            config: snap.config,
            v4If: snap.v4Interface,
            v6If: snap.v6Interface
        )
        let shouldIgnore = runtime.withLock { state in
            shouldIgnorePathEvent(
                wake: wake,
                gateFailure: nil,
                lastPass: state.lastGuardPass,
                newSignature: newSig,
                lastSignature: state.verifiedSignature,
                inFlightSignature: state.inFlightSignature
            )
        }
        if shouldIgnore { return }

        DispatchQueue.main.async { [self] in
            guard self.runtime.withLock({ $0.eventGuardActive }) else { return }
            self.scheduleEventRecheck(wake: wake, observedSignature: newSig)
        }
    }

    private func scheduleEventRecheck(wake: Bool, observedSignature: String) {
        pathDebounce?.cancel()
        if wake {
            runtime.withLock {
                $0.networkGeneration &+= 1
                $0.inFlightSignature = ""
            }
            setOverall(.checking)
            pendingWake = true
            nextFullCheckAt = .distantPast
            resumePendingWork()
        } else {
            let work = DispatchWorkItem { [weak self] in
                guard let self else { return }
                let proceed = self.runtime.withLock { state -> Bool in
                    guard state.eventGuardActive else { return false }
                    if !observedSignature.isEmpty && shouldIgnorePathEvent(
                        wake: false,
                        gateFailure: nil,
                        lastPass: state.lastGuardPass,
                        newSignature: observedSignature,
                        lastSignature: state.verifiedSignature,
                        inFlightSignature: state.inFlightSignature
                    ) {
                        return false
                    }
                    state.networkGeneration &+= 1
                    state.inFlightSignature = ""
                    return true
                }
                guard proceed else { return }
                self.setOverall(.checking)
                self.pendingPath = true
                self.nextFullCheckAt = .distantPast
                self.resumePendingWork()
            }
            pathDebounce = work
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.4, execute: work)
        }
    }

    @discardableResult
    private func resumePendingWork() -> Bool {
        let state = runtime.withLock { ($0.eventGuardActive, $0.directMode, $0.changingMode, $0.busy, $0.tickInFlight) }
        if state.1 || state.2 {
            pendingWake = false
            pendingPath = false
            pendingManualCheck = nil
            return false
        }
        guard !state.3, !state.4 else { return false }
        if let manual = pendingManualCheck {
            pendingManualCheck = nil
            pendingWake = false
            pendingPath = false
            runFullCheck(autofix: manual.autofix, openAfter: manual.openAfter, silentIfPass: false)
            return true
        }
        guard state.0 else { pendingWake = false; pendingPath = false; return false }
        if pendingWake {
            pendingWake = false
            pendingPath = false
            runFullCheck(autofix: true, openAfter: false, silentIfPass: false)
            return true
        }
        if pendingPath {
            pendingPath = false
            nextFullCheckAt = .distantPast
            runFullCheck(autofix: false, openAfter: false, silentIfPass: false)
            return true
        }
        return false
    }

    func logLine(_ s: String) {
        let line = "[\(currentHHMMSS())] \(s)"
        logLock.lock()
        defer { logLock.unlock() }
        logWriteCounter &+= 1
        if logWriteCounter % 256 == 0 {
            rotateLogIfNeeded(path: logFile)
        }
        if let h = FileHandle(forWritingAtPath: logFile) {
            _ = try? h.seekToEnd()
            if let data = (line + "\n").data(using: .utf8) {
                try? h.write(contentsOf: data)
            }
            try? h.close()
        } else {
            let directory = (logFile as NSString).deletingLastPathComponent
            try? FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true,
                                                     attributes: [.posixPermissions: 0o700])
            try? (line + "\n").write(toFile: logFile, atomically: true, encoding: .utf8)
        }
    }

    private func set(_ id: String, _ state: CheckState, _ detail: String = "") {
        DispatchQueue.main.async {
            if let i = self.checks.firstIndex(where: { $0.id == id }) {
                guard self.checks[i].state != state || self.checks[i].detail != detail else { return }
                self.checks[i].state = state
                self.checks[i].detail = detail
            }
        }
    }

    private func setOverall(_ o: Overall, touchTimestamp: Bool = true) {
        performOnMain {
            let changed = self.overall != o
            if changed { self.overall = o }
            if touchTimestamp {
                let ts = currentHHMMSS()
                if self.lastCheckAt != ts { self.lastCheckAt = ts }
            }
            if changed { self.onStatusChange?(o) }
        }
    }

    // MARK: - Verge / TUN / DNS Helpers

    private func syncVergeTun(_ on: Bool) {
        let path = NSString(string: "~/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/verge.yaml").expandingTildeInPath
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { return }
        let updated = content.components(separatedBy: "\n").map { line -> String in
            line.trimmingCharacters(in: .whitespaces).hasPrefix("enable_tun_mode:")
                ? "enable_tun_mode: \(on)"
                : line
        }.joined(separator: "\n")
        if updated != content {
            try? updated.write(toFile: path, atomically: true, encoding: .utf8)
        }
        logLine("已同步 Verge 配置 enable_tun_mode=\(on)")
    }

    private func isPrivateOrLinkLocalDNS(_ ip: String) -> Bool {
        if ip.hasPrefix("192.168.") || ip.hasPrefix("10.") || ip.lowercased().hasPrefix("fe80:") {
            return true
        }
        if ip.hasPrefix("172.") {
            let parts = ip.split(separator: ".")
            if parts.count == 4, let second = Int(parts[1]), (16...31).contains(second) {
                return true
            }
        }
        return false
    }

    private func waitForLocalTunnelReady(timeout: TimeInterval = 2.0) -> Bool {
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while ProcessInfo.processInfo.systemUptime < deadline {
            if localTunnelGateFailure() == nil { return true }
            Thread.sleep(forTimeInterval: 0.2)
        }
        return localTunnelGateFailure() == nil
    }

    // 确保 TUN 接管 IPv4/IPv6 路由，且仅在 Fake-IP 未生效时修补局域网系统 DNS（带 5s 超时保护防挂死）
    private func ensureTunAndDNS() {
        runtime.withLock { $0.repairActive = true }
        defer { runtime.withLock { $0.repairActive = false } }

        if let cfg = fetchCoreJSONResilient("/configs"),
           let tun = cfg["tun"] as? [String: Any],
           (tun["enable"] as? Bool) == true {
            let v6Addrs = tun["inet6-address"] as? [String] ?? []
            let expectedDevice = (tun["device"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let routeIf = tunnelRouteInterface() ?? ""
            let routeValid = routeIf.hasPrefix("utun") && !routeIf.contains("/")
                && (expectedDevice.isEmpty || routeIf == expectedDevice)
            if v6Addrs.isEmpty || !routeValid {
                _ = coreAPI("/configs", method: "PATCH", body: tunEnablePatch)
                _ = waitForLocalTunnelReady(timeout: 2.0)
                logLine("已补齐 TUN 路由接管 (route=\(routeIf.isEmpty ? "none" : routeIf))")
            }
        }

        if let ns = systemDNSServers().first, isPrivateOrLinkLocalDNS(ns),
           lookupIPv4("claude.ai", timeout: 1.5).ip?.hasPrefix("198.18.") != true {
            let vergeDir = NSString(string: "~/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev").expandingTildeInPath
            let setDnsScript = "/Applications/Clash Verge.app/Contents/Resources/resources/set_dns.sh"
            if FileManager.default.fileExists(atPath: setDnsScript) {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: "/bin/bash")
                p.arguments = [setDnsScript, "114.114.114.114"]
                p.currentDirectoryURL = URL(fileURLWithPath: vergeDir)
                p.standardOutput = FileHandle.nullDevice
                p.standardError = FileHandle.nullDevice
                if (try? p.run()) != nil {
                    let deadline = ProcessInfo.processInfo.systemUptime + 5.0
                    while p.isRunning && ProcessInfo.processInfo.systemUptime < deadline {
                        Thread.sleep(forTimeInterval: 0.05)
                    }
                    if p.isRunning { p.terminate() }
                }
                _ = waitForLocalTunnelReady(timeout: 2.0)
                logLine("系统 DNS 原为局域网 (\(ns))，已自动补设为 114.114.114.114 交给 TUN 接管")
            }
        }
    }

    private func tunEnabled() -> Bool? {
        guard let cfg = fetchCoreJSONResilient("/configs"),
              let tun = cfg["tun"] as? [String: Any] else { return nil }
        return tun["enable"] as? Bool
    }

    // MARK: - Probes (In-Process)

    private func probeEgress(session: URLSession) -> (loc: String, ip: String)? {
        let trace = httpFetch(session: session, url: "https://www.cloudflare.com/cdn-cgi/trace", timeout: 6)
        if let parsed = parseCloudflareTrace(trace) { return parsed }
        let info = httpFetch(session: session, url: "https://ipinfo.io/json", timeout: 6)
        if let j = parseJSON(info), let loc = j["country"] as? String, !loc.isEmpty {
            return (loc, j["ip"] as? String ?? "")
        }
        return nil
    }

    private func probeAnthropic(session: URLSession) -> Bool {
        probeAnthropicLive(primarySession: session)
    }

    // MARK: - Full Check (Concurrent Remote Probes, Zero Subprocesses, Race-Free State Machine)

    func runFullCheck(autofix: Bool, openAfter: Bool, silentIfPass: Bool = false) {
        let startDecision = runtime.withLock { state -> (canRun: Bool, generation: UInt64, wasPass: Bool) in
            if state.directMode || state.changingMode {
                return (false, 0, false)
            }
            if state.busy || state.tickInFlight {
                if autofix || openAfter {
                    let prev = self.pendingManualCheck
                    self.pendingManualCheck = (
                        autofix: autofix || (prev?.autofix ?? false),
                        openAfter: openAfter || (prev?.openAfter ?? false)
                    )
                } else if !silentIfPass {
                    self.pendingPath = true
                }
                return (false, 0, false)
            }
            state.busy = true
            return (true, state.networkGeneration, state.lastGuardPass)
        }
        guard startDecision.canRun else { return }

        let generation = startDecision.generation
        let quietBackgroundAudit = silentIfPass && startDecision.wasPass && !autofix && !openAfter
        busy = true
        if !quietBackgroundAudit {
            busyText = "检测中…"
            checks = checkTemplate
            setOverall(.checking, touchTimestamp: false)
        }

        q.async {
            var recheckAfterRepair = false
            var nextCheck = Date.distantPast
            let startSig = self.computeNetworkSignature()
            self.runtime.withLock { $0.inFlightSignature = startSig }

            func recordFailedCheck(clashInstalled: Bool) {
                self.runtime.withLock {
                    $0.lastGuardPass = false
                    $0.hasFailedSinceStart = true
                }
                let canAutoRepair = clashInstalled && (
                    autofix || (self.runtime.withLock({ $0.eventGuardActive }) && Date() >= self.nextAutoRecoveryAt)
                )
                if canAutoRepair {
                    if !autofix { self.nextAutoRecoveryAt = Date().addingTimeInterval(300) }
                    self.logLine("开始自动修复")
                    recheckAfterRepair = self.autoFixOnce()
                    self.logLine(recheckAfterRepair ? "修复完成，转入全量复检" : "修复失败")
                }
                if !recheckAfterRepair { self.setOverall(.fail) }
            }

            defer {
                let shouldRecheck = recheckAfterRepair
                let scheduledNext = nextCheck
                self.runtime.withLock { $0.inFlightSignature = "" }
                DispatchQueue.main.async {
                    self.runtime.withLock { $0.busy = false }
                    self.busy = false
                    self.busyText = ""
                    self.nextFullCheckAt = scheduledNext
                    if shouldRecheck && self.runtime.withLock({ $0.networkGeneration == generation && !$0.directMode }) {
                        self.runFullCheck(autofix: false, openAfter: openAfter, silentIfPass: false)
                    } else if self.resumePendingWork() {
                        return
                    } else if self.overall == .checking && !self.directMode {
                        // 防止路径世代号在中途推进后遗留孤立的 CHECKING 状态
                        self.runFullCheck(autofix: false, openAfter: openAfter, silentIfPass: false)
                    }
                }
            }

            var notifiedEarly = false
            if !quietBackgroundAudit {
                self.set("tun", .running)
                self.set("core", .running)
            }
            let local = checkLocalProtection(
                tunnelFailure: { verifiedLocalTunnelGateFailure() },
                readVersion: { fetchCoreJSONResilient("/version")?["version"] as? String },
                cutIfRunning: { reason in
                    guard self.hasRunningClaude() else { return true }
                    let stopped = self.cutClaudeAndWait(gracePeriod: 0.3, timeout: 3.5)
                    let status = stopped ? "已断开 Claude" : "未能确认 Claude 已退出"
                    self.logLine("本地检查未通过：\(reason)，\(status)")
                    if !notifiedEarly { notifyUser("⚠️ \(reason)，\(status)") }
                    notifiedEarly = true
                    self.runtime.withLock { $0.failureNotified = true }
                    return stopped
                },
                repair: self.ensureTunAndDNS
            )

            let ver = local.version
            let tunOK = local.failure == nil
            self.set("core", ver == nil ? .fail : .ok, ver.map { "mihomo \($0)" } ?? "代理内核接口不可达")
            self.set("tun", tunOK ? .ok : .fail, local.failure ?? "已开启 · IPv4/IPv6 / Fake-IP 已接管")
            let clashInstalled = NSWorkspace.shared.urlForApplication(withBundleIdentifier: clashBundleID) != nil
            guard local.canProbe else {
                nextCheck = Date().addingTimeInterval(15)
                let reason = local.failure ?? "代理内核接口不可达"
                self.logLine("本地检查未通过：\(reason)，跳过公网探测")
                recordFailedCheck(clashInstalled: local.stopped && clashInstalled)
                return
            }

            var appsOK = true
            if !quietBackgroundAudit { self.set("claudeApp", .running) }
            if let p = resolveRealClaudeAppPath() {
                self.set("claudeApp", .ok, (p as NSString).lastPathComponent)
            } else {
                self.set("claudeApp", .fail, "未找到，可能被更新/移动")
                appsOK = false
            }
            if !quietBackgroundAudit { self.set("clashApp", .running) }
            self.set("clashApp", clashInstalled ? .ok : .fail, clashInstalled ? "" : "未找到，可能被更新/移动")
            if !clashInstalled { appsOK = false }

            let fp = probeSystemFingerprint()
            self.set("fingerprint", fp.ok ? .ok : .warn, fp.detail)

            if !quietBackgroundAudit {
                for id in ["egress", "egress2", "v6", "stun", "api"] { self.set(id, .running) }
            }

            // 5 路公网探针并发执行，单次全检耗时从串行 6~30 秒降至约 1 秒，完成后立即销毁临时连接池释放内存
            let session = makeDirectURLSession()
            defer { session.finishTasksAndInvalidate() }

            let group = DispatchGroup()
            let probeLock = NSLock()
            var cfResult: (loc: String, ip: String)?
            var info2Result: [String: Any]?
            var v6RouteIf = ipv6RouteInterface() ?? ""
            var v6Result: (loc: String, ip: String)?
            var stunIP = ""
            var apiOK = false

            group.enter()
            DispatchQueue.global(qos: .utility).async {
                defer { group.leave() }
                let r = self.probeEgress(session: session)
                probeLock.lock(); cfResult = r; probeLock.unlock()
            }

            group.enter()
            DispatchQueue.global(qos: .utility).async {
                defer { group.leave() }
                let j = parseJSON(httpFetch(session: session, url: "https://ipinfo.io/json", timeout: 6))
                probeLock.lock(); info2Result = j; probeLock.unlock()
            }

            group.enter()
            DispatchQueue.global(qos: .utility).async {
                defer { group.leave() }
                let rIf = ipv6RouteInterface() ?? ""
                let v6 = rIf.hasPrefix("utun") ? probeIPv6CloudflareResilient() : nil
                probeLock.lock(); v6RouteIf = rIf; v6Result = v6; probeLock.unlock()
            }

            group.enter()
            DispatchQueue.global(qos: .utility).async {
                defer { group.leave() }
                let ip = probeSTUNConcurrent(timeout: 2.2)
                probeLock.lock(); stunIP = ip; probeLock.unlock()
            }

            group.enter()
            DispatchQueue.global(qos: .utility).async {
                defer { group.leave() }
                let ok = self.probeAnthropic(session: session)
                probeLock.lock(); apiOK = ok; probeLock.unlock()
            }

            group.wait()

            var egressOK = false
            var cfIP = ""
            var egressText = "无法获取"
            if let e = cfResult {
                cfIP = e.ip
                egressText = "\(e.loc) · \(e.ip)"
                DispatchQueue.main.async {
                    if self.egressInfo != egressText { self.egressInfo = egressText }
                }
                if blockedRegions.contains(e.loc) {
                    self.set("egress", .fail, "\(e.loc) 属受限地区")
                } else {
                    self.set("egress", .ok, egressText)
                    egressOK = true
                }
            } else {
                self.set("egress", .fail, "无法获取出口信息")
                DispatchQueue.main.async {
                    if self.egressInfo != "无法获取" { self.egressInfo = "无法获取" }
                }
            }

            var egress2OK = false
            let c2 = info2Result?["country"] as? String ?? ""
            let ip2 = info2Result?["ip"] as? String ?? ""
            if c2.isEmpty {
                self.set("egress2", .warn, "复核源不可达")
                egress2OK = egressOK
            } else if blockedRegions.contains(c2) {
                self.set("egress2", .fail, "\(c2) 属受限地区")
            } else if ip2 != cfIP && !cfIP.isEmpty {
                self.set("egress2", .warn, "\(c2) · \(ip2)（两源 IP 不同）")
                egress2OK = true
            } else {
                self.set("egress2", .ok, "\(c2) · \(ip2)")
                egress2OK = true
            }

            var v6OK = false
            if !v6RouteIf.hasPrefix("utun") {
                self.set("v6", .fail, "IPv6 路由未进 TUN (interface=\(v6RouteIf.isEmpty ? "无" : v6RouteIf))")
            } else if let v6 = v6Result {
                if blockedRegions.contains(v6.loc) {
                    self.set("v6", .fail, "IPv6 泄漏至 \(v6.loc) (\(v6.ip))！")
                } else {
                    self.set("v6", .ok, "\(v6RouteIf) → \(v6.loc) · \(v6.ip)")
                    v6OK = true
                }
            } else {
                self.set("v6", .fail, "IPv6 探测超时或未知（路由=\(v6RouteIf)，未放行）")
            }

            var stunOK = false
            if stunIP.isEmpty {
                self.set("stun", .ok, "UDP 不通（无泄漏面）")
                stunOK = true
            } else if stunIP == cfIP {
                self.set("stun", .ok, "UDP 与出口一致")
                stunOK = true
            } else {
                let rawCountry = httpFetch(session: session, url: "https://ipinfo.io/\(stunIP)/country", timeout: 5)
                let sc = sanitizeCountryCode(rawCountry) ?? "未知"
                if blockedRegions.contains(sc) {
                    self.set("stun", .fail, "UDP 泄漏真实 IP \(stunIP)（\(sc)）！")
                } else {
                    self.set("stun", .warn, "UDP 出口 \(stunIP)（\(sc)）")
                    stunOK = true
                }
            }

            self.set("api", apiOK ? .ok : .fail, apiOK ? "地区已放行" : "被拒或不可达")

            // 公网探测耗时约 1 秒，收口前再做一次毫秒级本地复核，防中途掉隧道蒙混过关
            let postSnap = evaluateVerifiedLocalTunnelGateWithConfig()
            let postLocalFailure = tunOK ? postSnap.failure : local.failure
            if let postLocalFailure {
                self.set("tun", .fail, postLocalFailure)
            }

            let hardChecks: [(Bool, String)] = [
                (appsOK, "应用未找到"),
                (ver != nil, "代理内核接口不可达"),
                (postLocalFailure == nil, postLocalFailure ?? "TUN 已接管"),
                (egressOK, "出口检查未通过"),
                (egress2OK, "出口复核未通过"),
                (v6OK, "IPv6 检查未通过"),
                (stunOK, "UDP 检查未通过"),
                (apiOK, "Anthropic API 被拒或不可达")
            ]
            let pass = hardChecks.allSatisfy { $0.0 }
            nextCheck = Date().addingTimeInterval(pass ? 300 : 60)

            let endSig = self.computeNetworkSignature(
                config: postSnap.config,
                v4If: postSnap.v4Interface,
                v6If: postSnap.v6Interface
            )
            if !quietBackgroundAudit || !pass {
                self.logLine("内核接口: \(coreClient.socket ?? "不可达") · 本地检查: \(postLocalFailure ?? "通过")")
                self.logLine("检测完成: \(pass ? "PASS" : "FAILED") 出口=\(egressText)\(fp.ok ? "" : " ⚠️指纹:\(fp.detail)")")
            }

            if !pass {
                let reason = hardChecks.filter { !$0.0 }.map { $0.1 }.joined(separator: "；")
                self.logLine("未通过原因: \(reason)")
                if self.hasRunningClaude() {
                    let stopped = self.cutClaudeAndWait(gracePeriod: 0.35, timeout: 3.5)
                    let status = stopped ? "已断开 Claude" : "未能确认 Claude 已退出"
                    self.logLine("全量检查未通过，\(status)")
                    notifyUser("⚠️ \(reason)，\(status)")
                    self.runtime.withLock { $0.failureNotified = true }
                    if !stopped {
                        self.runtime.withLock {
                            $0.lastGuardPass = false
                            $0.hasFailedSinceStart = true
                        }
                        self.setOverall(.fail)
                        return
                    }
                }
            }

            if pass {
                let commit = self.runtime.withLock { state -> (valid: Bool, recovered: Bool, notify: Bool) in
                    guard state.networkGeneration == generation, !state.directMode else {
                        return (false, false, false)
                    }
                    let recovered = state.hasFailedSinceStart
                    let notify = state.failureNotified
                    state.verifiedSignature = endSig
                    state.lastGuardPass = true
                    state.hasFailedSinceStart = false
                    state.failureNotified = false
                    state.inFlightSignature = ""
                    return (true, recovered, notify)
                }
                guard commit.valid else { return }
                if commit.recovered {
                    self.logLine("网络已恢复，全量检查通过")
                    if commit.notify { notifyUser("✅ 网络已恢复，全量检查通过") }
                }
                self.nextAutoRecoveryAt = .distantPast
                DispatchQueue.main.async {
                    guard self.runtime.withLock({ $0.networkGeneration == generation && !$0.directMode }) else { return }
                    self.setOverall(.pass)
                    if openAfter { self.openClaude() }
                }
            } else {
                recordFailedCheck(clashInstalled: clashInstalled)
            }
        }
    }

    // MARK: - Auto Fix (Deterministic Group Selection & Original Node Rollback)

    private func isHealthyRemotePath() -> (ok: Bool, loc: String, ip: String) {
        guard verifiedLocalTunnelGateFailure() == nil else { return (false, "", "") }
        let session = makeDirectURLSession()
        defer { session.finishTasksAndInvalidate() }

        let group = DispatchGroup()
        let lock = NSLock()
        var egress: (loc: String, ip: String)?
        var v6: (loc: String, ip: String)?
        var apiOK = false

        group.enter()
        DispatchQueue.global(qos: .utility).async {
            defer { group.leave() }
            let e = self.probeEgress(session: session)
            lock.lock(); egress = e; lock.unlock()
        }
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            defer { group.leave() }
            let r = probeIPv6CloudflareResilient()
            lock.lock(); v6 = r; lock.unlock()
        }
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            defer { group.leave() }
            let ok = self.probeAnthropic(session: session)
            lock.lock(); apiOK = ok; lock.unlock()
        }
        group.wait()

        guard let e = egress, !blockedRegions.contains(e.loc),
              let v6, !blockedRegions.contains(v6.loc),
              apiOK else {
            return (false, egress?.loc ?? "", egress?.ip ?? "")
        }
        return (true, e.loc, e.ip)
    }

    @discardableResult
    private func autoFixOnce() -> Bool {
        runtime.withLock { $0.repairActive = true }
        defer { runtime.withLock { $0.repairActive = false } }

        if fetchCoreJSONResilient("/version") == nil {
            DispatchQueue.main.async { self.busyText = "启动 Clash Verge…" }
            if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: clashBundleID) {
                NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
            }
            for _ in 0..<30 {
                Thread.sleep(forTimeInterval: 1)
                if fetchCoreJSONResilient("/version") != nil { break }
            }
            Thread.sleep(forTimeInterval: 1.5)
        }
        guard fetchCoreJSONResilient("/version") != nil else {
            logLine("修复失败：Clash 内核接口始终无响应")
            return false
        }

        if tunEnabled() == false {
            DispatchQueue.main.async { self.busyText = "开启 TUN…" }
            _ = coreAPI("/configs", method: "PATCH", body: tunEnablePatch)
            _ = waitForLocalTunnelReady(timeout: 2.5)
            let on = tunEnabled() == true
            logLine("TUN: \(on ? "已开启" : "开启失败")")
            if on { syncVergeTun(true) }
        }
        guard tunEnabled() == true else {
            logLine("修复失败：TUN 未开启或状态不可读")
            return false
        }

        var mode = (fetchCoreJSONResilient("/configs")?["mode"] as? String)?.lowercased() ?? ""
        let proxiesMap = fetchCoreJSONResilient("/proxies")?["proxies"] as? [String: [String: Any]] ?? [:]
        if mode == "direct" {
            let restoreMode = proxiesMap["PROXY"] != nil ? "rule" : "global"
            _ = coreAPI("/configs", method: "PATCH", body: "{\"mode\":\"\(restoreMode)\"}")
            mode = restoreMode
            logLine("代理模式: direct → \(restoreMode)")
        }

        ensureTunAndDNS()
        _ = waitForLocalTunnelReady(timeout: 2.0)

        let initialHealth = isHealthyRemotePath()
        if initialHealth.ok {
            logLine("当前线路验证正常 (\(initialHealth.loc) · \(initialHealth.ip))，无需切换节点")
            return true
        }

        // 确定性选择当前生效的 Selector 组，避免字典无序遍历在 GLOBAL 与 PROXY 间随机漂移
        let group: String = {
            if mode == "global" { return "GLOBAL" }
            if (proxiesMap["PROXY"]?["type"] as? String) == "Selector" { return "PROXY" }
            let selectors = proxiesMap.keys.sorted().filter { key in
                guard key != "GLOBAL",
                      (proxiesMap[key]?["type"] as? String) == "Selector",
                      let all = proxiesMap[key]?["all"] as? [String] else { return false }
                return all.contains { n in sgKeywords.contains { n.contains($0) } }
            }
            return selectors.first { $0.contains("手动") }
                ?? selectors.first { $0.contains("节点") }
                ?? selectors.first { $0.contains("漏网") }
                ?? selectors.first
                ?? "GLOBAL"
        }()

        guard let groupInfo = proxiesMap[group],
              let all = groupInfo["all"] as? [String] else {
            logLine("修复失败：读取代理组 \(group) 失败")
            return false
        }
        let originalNode = groupInfo["now"] as? String

        DispatchQueue.main.async { self.busyText = "并发测速新加坡节点…" }
        let sgCandidates = all.filter { n in sgKeywords.contains { n.contains($0) } }

        let testURL = pctEncode("https://cp.cloudflare.com/generate_204")
        let delayGroup = DispatchGroup()
        let delayLock = NSLock()
        var ranked: [(Int, String)] = []
        for node in sgCandidates.prefix(8) {
            delayGroup.enter()
            DispatchQueue.global(qos: .utility).async {
                defer { delayGroup.leave() }
                let resp = coreClient.callWithStatus(
                    "/proxies/\(pctEncode(node))/delay?timeout=2500&url=\(testURL)",
                    timeout: 3.2
                ).body ?? ""
                if let d = parseJSON(resp)?["delay"] as? Int, d > 0 {
                    delayLock.lock(); ranked.append((d, node)); delayLock.unlock()
                }
            }
        }
        delayGroup.wait()
        // 优先尝试用户配置的 Auto/Fallback 智能组（保留内核自动故障转移），不通过时再落到具体单节点
        ranked.sort { a, b in
            let aAuto = ["URLTest", "Fallback"].contains(proxiesMap[a.1]?["type"] as? String ?? "")
            let bAuto = ["URLTest", "Fallback"].contains(proxiesMap[b.1]?["type"] as? String ?? "")
            if aAuto != bAuto { return aAuto }
            return a.0 < b.0
        }
        logLine("可用 SG 节点: \(ranked.count)/\(sgCandidates.count)")

        for (delay, node) in ranked.prefix(4) {
            DispatchQueue.main.async { self.busyText = "切换 \(node)…" }
            if let data = try? JSONSerialization.data(withJSONObject: ["name": node]),
               let body = String(data: data, encoding: .utf8) {
                _ = coreAPI("/proxies/\(pctEncode(group))", method: "PUT", body: body)
            }
            logLine("切换 [\(group)] → \(node) (\(delay)ms)")
            Thread.sleep(forTimeInterval: 1.0)
            let health = isHealthyRemotePath()
            if health.ok {
                logLine("修复成功: \(node) 出口 \(health.loc) · \(health.ip)")
                return true
            }
        }

        // 所有候选均未通过时还原原节点，避免把用户的代理组留在失效备用线上
        if let originalNode, !originalNode.isEmpty,
           let data = try? JSONSerialization.data(withJSONObject: ["name": originalNode]),
           let body = String(data: data, encoding: .utf8) {
            _ = coreAPI("/proxies/\(pctEncode(group))", method: "PUT", body: body)
            logLine("所有候选节点均未通过，已还原 [\(group)] → \(originalNode)")
        } else {
            logLine("修复失败：所有候选节点均未通过")
        }
        return false
    }

    // MARK: - Direct Mode

    func setDirectMode(_ on: Bool) {
        let acquired = runtime.withLock { state -> Bool in
            guard on != state.directMode, !state.busy, !state.tickInFlight, !state.changingMode else { return false }
            state.changingMode = true
            state.busy = true
            state.inFlightSignature = ""
            return true
        }
        guard acquired else { return }
        pathDebounce?.cancel()
        pendingWake = false
        pendingPath = false
        pendingManualCheck = nil
        busy = true
        q.async {
            defer {
                DispatchQueue.main.async {
                    self.runtime.withLock {
                        $0.busy = false
                        $0.changingMode = false
                        if !on { $0.directMode = false }
                    }
                    self.busy = false
                    self.busyText = ""
                    if !on {
                        self.directMode = false
                        self.runFullCheck(autofix: true, openAfter: false, silentIfPass: false)
                    }
                }
            }
            if on {
                let claudeRunning = self.hasRunningClaude()
                if claudeRunning { DispatchQueue.main.async { self.busyText = "断开 Claude…" } }
                let cur = (fetchCoreJSONResilient("/configs")?["mode"] as? String) ?? "rule"
                let stopped = self.cutClaudeAndWait(gracePeriod: 1.2, timeout: 4.0)
                guard stopped else {
                    self.runtime.withLock { $0.directMode = false }
                    DispatchQueue.main.async { self.directMode = false }
                    self.logLine("直连切换中止：仍有 Claude 进程未退出，保留代理与 TUN 防裸奔")
                    notifyUser("⚠️ Claude 进程未完全退出，已取消切直连以防裸奔")
                    return
                }
                if cur != "direct" { self.savedClashMode = cur }
                if claudeRunning { notifyUser("直连模式：已断开 Claude，守护暂停") }
                _ = coreAPI("/configs", method: "PATCH", body: "{\"mode\":\"direct\"}")
                _ = coreAPI("/configs", method: "PATCH", body: "{\"tun\":{\"enable\":false}}")
                self.syncVergeTun(false)
                self.runtime.withLock {
                    $0.directMode = true
                    $0.lastGuardPass = false
                    $0.verifiedSignature = ""
                }
                DispatchQueue.main.async { self.directMode = true }
                self.logLine("进入直连模式（原模式 \(self.savedClashMode)，TUN 已关，守护暂停\(claudeRunning ? "，已断开 Claude" : "")）")
                self.setOverall(.direct)
            } else {
                _ = coreAPI("/configs", method: "PATCH", body: self.tunEnablePatch)
                self.syncVergeTun(true)
                self.ensureTunAndDNS()
                _ = coreAPI("/configs", method: "PATCH", body: "{\"mode\":\"\(self.savedClashMode)\"}")
                self.logLine("退出直连模式，恢复 \(self.savedClashMode)，重新安检")
                _ = self.waitForLocalTunnelReady(timeout: 2.0)
            }
        }
    }

    // MARK: - Realtime Guard (Single-Snapshot Heartbeat, Zero Main-Thread Wakeup Noise)

    private func guardTick() {
        let canStart = runtime.withLock { state -> Bool in
            guard state.monitoring, !state.busy, !state.directMode, !state.changingMode, !state.tickInFlight else {
                return false
            }
            state.tickInFlight = true
            return true
        }
        guard canStart else { return }
        let fullCheckDue = Date() >= nextFullCheckAt

        q.async {
            var needsFullCheck = false
            var silentFullCheck = false
            var repairing = false
            defer {
                let didRepair = repairing
                let triggerCheck = needsFullCheck
                let quietCheck = silentFullCheck
                DispatchQueue.main.async {
                    self.runtime.withLock {
                        $0.tickInFlight = false
                        if didRepair { $0.busy = false }
                    }
                    if didRepair { self.busy = false; self.busyText = "" }
                    if self.resumePendingWork() { return }
                    if triggerCheck {
                        self.runFullCheck(autofix: false, openAfter: false, silentIfPass: quietCheck)
                    }
                }
            }

            let snap = evaluateVerifiedLocalTunnelGateWithConfig()
            if let localFailure = snap.failure {
                self.set("tun", .fail, localFailure)
                self.handleRealtimeFailure(reason: localFailure, repairing: &repairing, needsFullCheck: &needsFullCheck)
                return
            }

            // 本地硬门槛通过：直接复用本次快照中的 /configs 与选路网卡比对签名，不重复查 socket/路由表
            let currentSig = self.computeNetworkSignature(
                config: snap.config,
                v4If: snap.v4Interface,
                v6If: snap.v6Interface
            )
            let state = self.runtime.withLock { ($0.lastGuardPass, $0.verifiedSignature) }
            if state.0 && !state.1.isEmpty && currentSig != state.1 {
                needsFullCheck = true
                silentFullCheck = false
                return
            }
            if fullCheckDue {
                needsFullCheck = true
                silentFullCheck = state.0
            }
        }
    }

    private func handleRealtimeFailure(reason: String, repairing: inout Bool, needsFullCheck: inout Bool) {
        let alreadyNotified = runtime.withLock { state -> Bool in
            let prev = state.failureNotified
            state.lastGuardPass = false
            state.hasFailedSinceStart = true
            state.failureNotified = true
            return prev
        }
        DispatchQueue.main.async { self.nextFullCheckAt = .distantPast }
        setOverall(.fail)
        if hasRunningClaude() {
            let stopped = cutClaudeAndWait(gracePeriod: 0.35, timeout: 3.5)
            let status = stopped ? "已断开 Claude" : "未能确认 Claude 已退出"
            logLine("⚠️ \(reason)，\(status)")
            notifyUser("⚠️ \(reason)，\(status)")
            guard stopped else { return }
        } else if !alreadyNotified {
            logLine("守护未通过：\(reason)（Claude 未运行）")
        }

        guard Date() >= nextAutoRecoveryAt else { return }
        let acquired = runtime.withLock { state -> Bool in
            guard !state.busy, !state.directMode, !state.changingMode else { return false }
            state.busy = true
            return true
        }
        guard acquired else { return }
        repairing = true
        DispatchQueue.main.async {
            self.busy = true
            self.busyText = "自动修复中…"
        }
        nextAutoRecoveryAt = Date().addingTimeInterval(300)
        for attempt in 1...3 {
            logLine("自动恢复尝试 \(attempt)/3…")
            DispatchQueue.main.async { self.busyText = "自动恢复 \(attempt)/3…" }
            if autoFixOnce() {
                logLine("第 \(attempt) 次恢复完成，转入全量复检")
                needsFullCheck = true
                return
            }
            if attempt < 3 { Thread.sleep(forTimeInterval: 2) }
        }
        nextAutoRecoveryAt = Date().addingTimeInterval(300)
        logLine("自动恢复失败，5 分钟后重试；实时检测继续")
        notifyUser("❌ 自动恢复失败，请检查 Clash / 网络；5 分钟后重试")
    }

    // MARK: - Managed Claude Process Control

    private var runningClaudeApps: [NSRunningApplication] {
        NSRunningApplication.runningApplications(withBundleIdentifier: claudeBundleID).filter {
            var info = proc_bsdinfo()
            let size = Int32(MemoryLayout.size(ofValue: info))
            if proc_pidinfo($0.processIdentifier, PROC_PIDTBSDINFO, 0, &info, size) == size {
                return info.pbi_status != 5
            }
            return errno != ESRCH && errno != ENOENT
        }
    }

    private func hasRunningClaude() -> Bool {
        !runningClaudeApps.isEmpty || !listManagedClaudePIDs().isEmpty
    }

    @discardableResult
    private func cutClaudeAndWait(gracePeriod: TimeInterval, timeout: TimeInterval) -> Bool {
        var completeScan = true
        var remaining: [pid_t] = []
        let stopped = terminateManagedClaude(
            gracePeriod: gracePeriod, timeout: timeout,
            listPIDs: {
                completeScan = true
                remaining = listManagedClaudePIDs { completeScan = false }
                return remaining
            },
            hasRunningApp: { !self.runningClaudeApps.isEmpty },
            requestAppTerminate: {
                let apps = self.runningClaudeApps
                performOnMain { for app in apps { app.terminate() } }
            },
            forceAppTerminate: {
                let apps = self.runningClaudeApps
                performOnMain { for app in apps { app.forceTerminate() } }
            },
            sendSignal: { pid, sig in
                if isManagedClaudePID(pid, currentUID: getuid(), selfPID: getpid(), homeDir: NSHomeDirectory(),
                                      appContentsRoots: nil, onIncompleteScan: {}) {
                    _ = Darwin.kill(pid, sig)
                }
            }
        )
        if !stopped || !completeScan {
            let pids = Set(remaining + runningClaudeApps.map(\.processIdentifier)).sorted()
            logLine("未能确认 Claude 已退出，残留 PID：\(pids)\(completeScan ? "" : "（进程扫描不完整）")")
            return false
        }
        return true
    }

    // MARK: - Actions

    func openClaude() {
        guard let path = resolveRealClaudeAppPath() else {
            logLine("打开失败：找不到 Claude.app")
            return
        }
        NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: path), configuration: NSWorkspace.OpenConfiguration()) {
            [weak self] _, error in
            self?.logLine(error.map { "打开 Claude 失败：\($0.localizedDescription)" } ?? "已打开 Claude")
        }
    }
}

// MARK: - UI (Lazy-Instantiated On Click to Keep Idle Footprint Minimal)

struct MascotView: View {
    let overall: Overall
    static let mascot: NSImage? = {
        guard let p = Bundle.main.path(forResource: "AppIcon", ofType: "icns") else { return nil }
        return NSImage(contentsOfFile: p)
    }()
    var body: some View {
        ZStack {
            if let img = Self.mascot {
                Image(nsImage: img)
                    .resizable().interpolation(.high)
                    .frame(width: 84, height: 84)
                    .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
                    .shadow(color: .black.opacity(0.15), radius: 5, y: 2)
                    .saturation(overall == .fail ? 0.35 : 1)
            } else {
                Circle()
                    .fill(LinearGradient(
                        colors: [Color(red: 1, green: 0.75, blue: 0.35), Color(red: 0.95, green: 0.55, blue: 0.2)],
                        startPoint: .topLeading, endPoint: .bottomTrailing))
                    .frame(width: 84, height: 84)
                Text("🐶").font(.system(size: 48))
            }
            VStack {
                Spacer()
                HStack {
                    Spacer()
                    Text({ switch overall {
                        case .checking: return "🔍"
                        case .pass: return ""
                        case .fail: return "🚨"
                        case .direct: return "💤"
                    } }())
                        .font(.system(size: 24))
                        .offset(x: 6, y: 4)
                }
            }.frame(width: 84, height: 84)
        }
    }
}

struct CheckRow: View {
    let item: CheckItem
    var icon: some View {
        Group {
            switch item.state {
            case .pending: Image(systemName: "circle.dotted").foregroundColor(.secondary)
            case .running: ProgressView().controlSize(.small)
            case .ok: Image(systemName: "checkmark.circle.fill").foregroundColor(.green)
            case .warn: Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.orange)
            case .fail: Image(systemName: "xmark.circle.fill").foregroundColor(.red)
            }
        }.frame(width: 18)
    }
    var body: some View {
        HStack(spacing: 8) {
            icon
            Text(item.title).font(.system(size: 12))
            Spacer()
            Text(item.detail)
                .font(.system(size: 11))
                .foregroundColor(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(maxWidth: 150, alignment: .trailing)
                .help(item.detail)
        }
    }
}

struct GuardView: View {
    @ObservedObject var model: GuardModel

    var statusColor: Color {
        switch model.overall {
        case .checking: return .gray
        case .pass: return Color(red: 0.15, green: 0.65, blue: 0.35)
        case .fail: return Color(red: 0.85, green: 0.25, blue: 0.25)
        case .direct: return Color(red: 0.3, green: 0.5, blue: 0.9)
        }
    }
    var statusText: String {
        switch model.overall {
        case .checking: return "CHECKING"
        case .pass: return "PASS"
        case .fail: return "FAILED"
        case .direct: return "DIRECT"
        }
    }

    var body: some View {
        VStack(spacing: 12) {
            HStack(spacing: 14) {
                MascotView(overall: model.overall)
                VStack(alignment: .leading, spacing: 4) {
                    Text("ClaudeGuard").font(.system(size: 15, weight: .bold))
                    Text(model.directMode ? "守卫犬 Guardy 休息中" : "守卫犬 Guardy 在岗")
                        .font(.system(size: 11)).foregroundColor(.secondary)
                    HStack(spacing: 6) {
                        Circle().fill(statusColor).frame(width: 7, height: 7)
                        Text(statusText)
                            .font(.system(size: 12, weight: .semibold, design: .rounded))
                            .foregroundColor(statusColor)
                    }
                    .padding(.horizontal, 10).padding(.vertical, 4)
                    .background(Capsule().fill(statusColor.opacity(0.14)))
                }
                Spacer()
            }

            if model.overall == .pass && !model.directMode {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.shield.fill")
                        .foregroundColor(Color(red: 0.16, green: 0.66, blue: 0.36))
                        .font(.system(size: 16, weight: .bold))
                    VStack(alignment: .leading, spacing: 1) {
                        Text("环境安全，正在守护")
                            .font(.system(size: 12.5, weight: .semibold))
                        Text("通过 \(model.checks.filter { $0.state == .ok }.count) 项 · 提示 \(model.checks.filter { $0.state == .warn }.count) 项")
                            .font(.system(size: 10.5)).foregroundColor(.secondary)
                            .lineLimit(1).truncationMode(.middle)
                    }
                    Spacer()
                }
                .padding(.horizontal, 10).padding(.vertical, 8)
                .background(RoundedRectangle(cornerRadius: 10)
                    .fill(Color(red: 0.16, green: 0.66, blue: 0.36).opacity(0.12)))
            }

            Picker("", selection: Binding(
                get: { model.directMode ? 1 : 0 },
                set: { model.setDirectMode($0 == 1) }
            )) {
                Label("守护模式", systemImage: "shield.fill").tag(0)
                Label("直连模式", systemImage: "arrow.up.right").tag(1)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .disabled(model.busy)

            HStack {
                Image(systemName: "globe.asia.australia.fill").foregroundColor(.secondary).font(.system(size: 11))
                Text("出口 \(model.egressInfo)").font(.system(size: 11)).foregroundColor(.secondary)
                Spacer()
                Text("上次检测 \(model.lastCheckAt)").font(.system(size: 10)).foregroundColor(.secondary)
            }
            if !model.directMode {
                HStack {
                    Image(systemName: "point.3.connected.trianglepath.dotted")
                        .foregroundColor(.secondary).font(.system(size: 11))
                    Text("线路 \(model.currentNode)").font(.system(size: 11)).foregroundColor(.secondary)
                        .lineLimit(1).truncationMode(.middle)
                    Spacer()
                }
            }

            Divider()

            if model.directMode {
                VStack(spacing: 8) {
                    Image(systemName: "moon.zzz.fill")
                        .font(.system(size: 26))
                        .foregroundColor(Color(red: 0.3, green: 0.5, blue: 0.9))
                    Text("直连模式：流量不走代理，守护已暂停")
                        .font(.system(size: 12))
                    Text("Claude 已断开保护 · 切回守护模式将自动恢复代理并重新安检")
                        .font(.system(size: 10.5)).foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
            } else {
                VStack(spacing: 7) {
                    ForEach(model.checks) { CheckRow(item: $0) }
                }
            }

            if model.busy {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text(model.busyText).font(.system(size: 11)).foregroundColor(.secondary)
                    Spacer()
                }
            }

            Divider()

            if !model.directMode {
                HStack(spacing: 8) {
                    if model.overall == .pass {
                        Button(action: { model.openClaude() }) {
                            Label("打开 Claude", systemImage: "arrow.up.forward.app.fill")
                                .frame(maxWidth: .infinity)
                        }
                        .controlSize(.large)
                        .buttonStyle(.borderedProminent)
                        .disabled(model.busy)
                    } else {
                        Button(action: { model.runFullCheck(autofix: true, openAfter: true, silentIfPass: false) }) {
                            Label("一键修复并打开", systemImage: "wand.and.stars")
                                .frame(maxWidth: .infinity)
                        }
                        .controlSize(.large)
                        .buttonStyle(.borderedProminent)
                        .tint(.orange)
                        .disabled(model.busy)
                    }
                    Button(action: { model.runFullCheck(autofix: true, openAfter: false, silentIfPass: false) }) {
                        Image(systemName: "arrow.clockwise")
                    }
                    .controlSize(.large)
                    .disabled(model.busy)
                    .help("刷新：重新检测，发现异常自动修复")
                }
            }

            HStack {
                if model.directMode {
                    Text("需要用 Claude 时切回守护模式").font(.system(size: 11)).foregroundColor(.secondary)
                } else {
                    Toggle(isOn: $model.monitoring) {
                        Text("实时守护（失守自动断开 Claude）").font(.system(size: 11))
                    }
                    .toggleStyle(.switch)
                    .controlSize(.mini)
                }
                Spacer()
                Button("三方复检") {
                    NSWorkspace.shared.open(URL(string: "https://fuck-claude.vercel.app/zh/")!)
                }
                .buttonStyle(.plain)
                .font(.system(size: 11))
                .foregroundColor(Color(red: 0.35, green: 0.55, blue: 0.92))
                .help("在浏览器打开 FuckClaude 检测器，独立验证指纹环境")
                Button("退出") { NSApp.terminate(nil) }
                    .buttonStyle(.plain)
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
            }
        }
        .padding(14)
        .frame(width: 320)
    }
}

// MARK: - App Bootstrap

final class AppDelegate: NSObject, NSApplicationDelegate, NSUserNotificationCenterDelegate {
    var statusItem: NSStatusItem!
    var panel: NSPanel?
    var hostController: NSHostingController<GuardView>?
    var clickMonitor: Any?
    let model = GuardModel()

    func statusImage(for overall: Overall) -> NSImage? {
        let name: String
        let color: NSColor
        switch overall {
        case .checking:
            name = "shield.lefthalf.filled"
            color = .secondaryLabelColor
        case .pass:
            name = "checkmark.shield.fill"
            color = NSColor(calibratedRed: 0.16, green: 0.66, blue: 0.36, alpha: 1)
        case .fail:
            name = "exclamationmark.shield.fill"
            color = NSColor(calibratedRed: 0.88, green: 0.26, blue: 0.24, alpha: 1)
        case .direct:
            name = "shield.slash.fill"
            color = NSColor(calibratedRed: 0.35, green: 0.55, blue: 0.92, alpha: 1)
        }
        let cfg = NSImage.SymbolConfiguration(pointSize: 15, weight: .semibold)
            .applying(.init(paletteColors: [color]))
        let img = NSImage(systemSymbolName: name, accessibilityDescription: "ClaudeGuard")?
            .withSymbolConfiguration(cfg)
        img?.isTemplate = false
        return img
    }

    func ensurePanel() -> NSPanel {
        if let panel { return panel }
        let host = NSHostingController(rootView: GuardView(model: model))
        host.safeAreaRegions = []
        let p = NSPanel(contentViewController: host)
        p.styleMask = [.titled, .fullSizeContentView, .nonactivatingPanel]
        p.titleVisibility = .hidden
        p.titlebarAppearsTransparent = true
        p.isMovable = false
        p.level = .statusBar
        p.isReleasedWhenClosed = false
        p.hidesOnDeactivate = false
        p.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        for b: NSWindow.ButtonType in [.closeButton, .miniaturizeButton, .zoomButton] {
            p.standardWindowButton(b)?.isHidden = true
        }
        hostController = host
        panel = p
        return p
    }

    @discardableResult
    func syncPanelContentSize() -> NSSize {
        let p = ensurePanel()
        guard let host = hostController else {
            p.layoutIfNeeded()
            return p.frame.size
        }
        host.view.layoutSubtreeIfNeeded()
        let fitting = host.view.fittingSize
        if fitting.width > 0 && fitting.height > 0 {
            p.setContentSize(fitting)
        }
        return p.frame.size
    }

    private func positionPanel(_ p: NSPanel) {
        let size = syncPanelContentSize()
        guard let btnWindow = statusItem?.button?.window,
              let screen = btnWindow.screen ?? NSScreen.main else { return }
        let icon = btnWindow.frame
        var x = icon.midX - size.width / 2
        let vis = screen.visibleFrame
        x = min(max(x, vis.minX + 8), vis.maxX - size.width - 8)
        let y = icon.minY - size.height - 6
        p.setFrame(NSRect(x: x, y: y, width: size.width, height: size.height), display: p.isVisible)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem.button?.image = statusImage(for: .checking)
        statusItem.button?.toolTip = "ClaudeGuard · 检测中"
        statusItem.button?.action = #selector(togglePopover)
        statusItem.button?.target = self

        model.onStatusChange = { [weak self] overall in
            guard let self else { return }
            self.statusItem.button?.image = self.statusImage(for: overall)
            self.statusItem.button?.toolTip = {
                switch overall {
                case .checking: return "ClaudeGuard · 检测中"
                case .pass: return "ClaudeGuard · PASS"
                case .fail: return "ClaudeGuard · FAILED"
                case .direct: return "ClaudeGuard · 直连模式（守护暂停）"
                }
            }()
            if let p = self.panel, p.isVisible {
                DispatchQueue.main.async { self.positionPanel(p) }
            }
        }
        model.logLine("=== ClaudeGuard 启动 ===")
        NSUserNotificationCenter.default.delegate = self
        model.start()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showPanel()
        return true
    }

    func userNotificationCenter(_ center: NSUserNotificationCenter,
                                shouldPresent notification: NSUserNotification) -> Bool {
        true
    }

    func userNotificationCenter(_ center: NSUserNotificationCenter,
                                didActivate notification: NSUserNotification) {
        showPanel()
    }

    func hidePanel() {
        panel?.orderOut(nil)
        if let m = clickMonitor { NSEvent.removeMonitor(m); clickMonitor = nil }
    }

    func showPanel() {
        let p = ensurePanel()
        guard statusItem?.button?.window != nil else { return }
        positionPanel(p)
        p.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        if clickMonitor == nil {
            clickMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
                self?.hidePanel()
            }
        }
    }

    @objc func togglePopover() {
        if panel?.isVisible == true { hidePanel() } else { showPanel() }
    }
}

private var daemonLockFD: Int32 = -1

private func acquireDaemonSingleInstanceLock() -> Bool {
    let lockPath = "/tmp/claudeguard-\(getuid()).lock"
    let fd = Darwin.open(lockPath, O_CREAT | O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR)
    guard fd >= 0 else { return true }
    var fl = Darwin.flock(
        l_start: 0,
        l_len: 0,
        l_pid: getpid(),
        l_type: Int16(F_WRLCK),
        l_whence: Int16(SEEK_SET)
    )
    if Darwin.fcntl(fd, F_SETLK, &fl) == -1 {
        Darwin.close(fd)
        return false
    }
    daemonLockFD = fd
    return true
}

if CommandLine.arguments.contains("--help") {
    print("ClaudeGuard [--help | --check-core | --check-gate]")
    exit(0)
}

// 只读诊断入口；启动脚本复用同一套内核寻址，不启动 UI 或自动修复。
if CommandLine.arguments.contains("--check-core") {
    let cfg = parseJSON(coreAPI("/configs"))
    let tun = (cfg?["tun"] as? [String: Any])?["enable"] as? Bool
    var result: [String: Any] = ["socket": coreClient.socket ?? "", "tun": tun.map { $0 as Any } ?? NSNull()]
    if tun == nil { result["error"] = "代理内核接口不可达或 TUN 状态不可读" }
    if let data = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]),
       let json = String(data: data, encoding: .utf8) {
        print(json)
    }
    exit(tun == true ? 0 : 1)
}

// 前门快速全链路自检入口（零子进程 + 并发探针）。
if CommandLine.arguments.contains("--check-gate") {
    let res = runHeadlessGateCheck()
    print(res.ok ? "✅ 环境通过（\(res.summary)）" : "❌ 环境未通过：\(res.summary)")
    exit(res.ok ? 0 : 1)
}

if !acquireDaemonSingleInstanceLock() { exit(0) }
let guardBundleID = Bundle.main.bundleIdentifier ?? "com.claudeguard.app"
if NSRunningApplication.runningApplications(withBundleIdentifier: guardBundleID).contains(where: {
    $0.processIdentifier != getpid()
}) { exit(0) }

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
