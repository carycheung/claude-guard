import AppKit
import SwiftUI

// MARK: - Constants

let clashBundleID = "io.github.clash-verge-rev.clash-verge-rev"
let claudeBundleID = "com.anthropic.claudefordesktop"
let mihomoSock = "/tmp/verge/verge-mihomo.sock"
let blockedRegions: Set<String> = ["CN", "HK", "MO", "RU"]
let sgKeywords = ["新加坡", "SG", "Singapore", "狮城"]
let logFile = NSString(string: "~/ClaudeGuard/guard.log").expandingTildeInPath

// MARK: - Shell helpers

@discardableResult
func sh(_ cmd: String, timeout: TimeInterval = 20) -> String {
    let p = Process()
    p.launchPath = "/bin/bash"
    p.arguments = ["-c", cmd]
    let out = Pipe()
    p.standardOutput = out
    p.standardError = Pipe()
    do { try p.run() } catch { return "" }
    DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
        if p.isRunning { p.terminate() }
    }
    // 先读到 EOF 再等退出，避免大输出填满 64KB 管道缓冲导致死锁
    let data = out.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return String(data: data, encoding: .utf8) ?? ""
}

func coreAPI(_ path: String, method: String = "GET", body: String? = nil) -> String {
    var cmd = "curl -s --max-time 5 --unix-socket \(mihomoSock) -X \(method) 'http://localhost\(path)'"
    if let b = body { cmd += " -d '\(b)'" }
    return sh(cmd, timeout: 8)
}

func parseJSON(_ s: String) -> [String: Any]? {
    guard let d = s.data(using: .utf8) else { return nil }
    return (try? JSONSerialization.jsonObject(with: d)) as? [String: Any]
}

func pctEncode(_ s: String) -> String {
    return s.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? s
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

final class GuardModel: ObservableObject {
    @Published var overall: Overall = .checking
    @Published var checks: [CheckItem] = []
    @Published var egressInfo: String = "—"
    @Published var monitoring: Bool = true {
        didSet { logLine(monitoring ? "实时守护已开启" : "实时守护已关闭") }
    }
    @Published var directMode: Bool = false
    @Published var currentNode: String = "—"
    private var savedClashMode: String = "global"

    // 写回 Verge 自己的配置文件，避免它的界面/重启状态与内核漂移
    private func syncVergeTun(_ on: Bool) {
        let f = NSString(string: "~/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/verge.yaml").expandingTildeInPath
        _ = sh("sed -i '' 's/^enable_tun_mode: .*/enable_tun_mode: \(on)/' '\(f)'", timeout: 5)
        logLine("已同步 Verge 配置 enable_tun_mode=\(on)")
    }

    private func refreshCurrentNode() {
        if let g = parseJSON(coreAPI("/proxies/GLOBAL")), let now = g["now"] as? String {
            DispatchQueue.main.async { self.currentNode = now }
        }
    }
    @Published var busy: Bool = false
    @Published var busyText: String = ""
    @Published var logLines: [String] = []
    @Published var lastCheckAt: String = "—"

    var onStatusChange: ((Overall) -> Void)?
    private var timer: Timer?
    private var lastGuardPass = true
    private let q = DispatchQueue(label: "guard.work")

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
        checks = checkTemplate
        runFullCheck(autofix: false, openAfter: false)
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            self?.guardTick()
        }
    }

    func logLine(_ s: String) {
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss"
        let line = "[\(f.string(from: Date()))] \(s)"
        DispatchQueue.main.async {
            self.logLines.append(line)
            if self.logLines.count > 200 { self.logLines.removeFirst(self.logLines.count - 200) }
        }
        if let h = FileHandle(forWritingAtPath: logFile) {
            h.seekToEndOfFile()
            h.write((line + "\n").data(using: .utf8)!)
            h.closeFile()
        } else {
            try? (line + "\n").write(toFile: logFile, atomically: true, encoding: .utf8)
        }
    }

    private func set(_ id: String, _ state: CheckState, _ detail: String = "") {
        DispatchQueue.main.async {
            if let i = self.checks.firstIndex(where: { $0.id == id }) {
                self.checks[i].state = state
                self.checks[i].detail = detail
            }
        }
    }

    private func setOverall(_ o: Overall) {
        DispatchQueue.main.async {
            self.overall = o
            let f = DateFormatter(); f.dateFormat = "HH:mm:ss"
            self.lastCheckAt = f.string(from: Date())
            self.onStatusChange?(o)
        }
    }

    // MARK: probes

    private func probeEgress() -> (loc: String, ip: String)? {
        let trace = sh("curl -s --max-time 6 https://www.cloudflare.com/cdn-cgi/trace", timeout: 8)
        var loc = "", ip = ""
        for line in trace.split(separator: "\n") {
            if line.hasPrefix("loc=") { loc = String(line.dropFirst(4)) }
            if line.hasPrefix("ip=") { ip = String(line.dropFirst(3)) }
        }
        if loc.isEmpty {
            let info = sh("curl -s --max-time 6 https://ipinfo.io/json", timeout: 8)
            if let j = parseJSON(info) {
                loc = j["country"] as? String ?? ""
                ip = j["ip"] as? String ?? ""
            }
        }
        return loc.isEmpty ? nil : (loc, ip)
    }

    private func probeAnthropic() -> Bool {
        let resp = sh("curl -s --max-time 8 -X POST https://api.anthropic.com/v1/messages -H 'content-type: application/json' -d '{}'", timeout: 10)
        return resp.contains("authentication_error")
    }

    private func tunEnabled() -> Bool? {
        guard let cfg = parseJSON(coreAPI("/configs")),
              let tun = cfg["tun"] as? [String: Any] else { return nil }
        return tun["enable"] as? Bool ?? false
    }

    // 本机指纹自查（参考 fuck-claude 风控模型：时区权重最高、语言次之）
    // 返回 (通过, 明细)；受限地区时区或中文首选语言即判 fail
    private func probeFingerprint() -> (ok: Bool, detail: String) {
        let tz = sh("readlink /etc/localtime | sed 's#.*/zoneinfo/##'", timeout: 4)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let cnTZ = ["Asia/Shanghai", "Asia/Urumqi", "Asia/Chongqing", "Asia/Harbin", "PRC"]
        let langsRaw = sh("defaults read -g AppleLanguages 2>/dev/null | tr -d ' \\n\"()'", timeout: 4)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let firstLang = langsRaw.split(separator: ",").first.map(String.init) ?? ""
        let tzBad = cnTZ.contains(tz)
        // 首选语言以 zh 开头即视为高风险（zh-Hans / zh-CN 等）
        let langBad = firstLang.lowercased().hasPrefix("zh")
        if tzBad {
            return (false, "时区 \(tz) 属中国时区")
        }
        if langBad {
            return (false, "首选语言 \(firstLang)（建议改英文）")
        }
        return (true, "时区 \(tz) · \(firstLang)")
    }

    // MARK: full check

    func runFullCheck(autofix: Bool, openAfter: Bool) {
        guard !busy, !directMode else { return }
        DispatchQueue.main.async {
            self.busy = true
            self.busyText = "检测中…"
            self.checks = self.checkTemplate
        }
        setOverall(.checking)
        q.async {
            defer { DispatchQueue.main.async { self.busy = false; self.busyText = "" } }

            // 1) App 健康检查（应用更新/卸载可能导致失效）
            var appsOK = true
            self.set("claudeApp", .running)
            if let p = NSWorkspace.shared.urlForApplication(withBundleIdentifier: claudeBundleID)?.path {
                self.set("claudeApp", .ok, (p as NSString).lastPathComponent)
            } else {
                self.set("claudeApp", .fail, "未找到，可能被更新/移动")
                appsOK = false
            }
            self.set("clashApp", .running)
            let clashInstalled = NSWorkspace.shared.urlForApplication(withBundleIdentifier: clashBundleID) != nil
            self.set("clashApp", clashInstalled ? .ok : .fail, clashInstalled ? "" : "未找到，可能被更新/移动")
            if !clashInstalled { appsOK = false }

            // 2) 内核接口
            self.set("core", .running)
            let ver = parseJSON(coreAPI("/version"))?["version"] as? String
            if let v = ver {
                self.set("core", .ok, "mihomo \(v)")
            } else {
                self.set("core", clashInstalled ? .warn : .fail, "接口无响应（Clash 未运行或更新后 socket 变了）")
            }

            // 3) TUN —— 硬性门槛：手动关 TUN 视为失守（修复此前 TUN 关闭仍 PASS 的 bug）
            self.set("tun", .running)
            var tunOK = false
            if let t = self.tunEnabled() {
                self.set("tun", t ? .ok : .fail, t ? "已开启" : "未开启（流量可能裸奔）")
                tunOK = t
            } else {
                self.set("tun", .fail, "无法读取 TUN 状态")
            }
            self.refreshCurrentNode()

            // 4) 出口三方交叉验证：Cloudflare + ipinfo 两个独立源 + IPv6 + STUN(UDP)
            self.set("egress", .running)
            var egressOK = false
            var cfIP = ""
            if let e = self.probeEgress() {
                cfIP = e.ip
                DispatchQueue.main.async { self.egressInfo = "\(e.loc) · \(e.ip)" }
                if blockedRegions.contains(e.loc) {
                    self.set("egress", .fail, "\(e.loc) 属受限地区")
                } else {
                    self.set("egress", .ok, "\(e.loc) · \(e.ip)")
                    egressOK = true
                }
            } else {
                self.set("egress", .fail, "无法获取出口信息")
                DispatchQueue.main.async { self.egressInfo = "无法获取" }
            }

            self.set("egress2", .running)
            var egress2OK = false
            let info2 = parseJSON(sh("curl -s --max-time 6 https://ipinfo.io/json", timeout: 8))
            let c2 = info2?["country"] as? String ?? ""
            let ip2 = info2?["ip"] as? String ?? ""
            if c2.isEmpty {
                self.set("egress2", .warn, "复核源不可达")
                egress2OK = egressOK  // 单源可用时不因复核源宕机而误杀
            } else if blockedRegions.contains(c2) {
                self.set("egress2", .fail, "\(c2) 属受限地区")
            } else if ip2 != cfIP && !cfIP.isEmpty {
                self.set("egress2", .warn, "\(c2) · \(ip2)（两源 IP 不同）")
                egress2OK = true
            } else {
                self.set("egress2", .ok, "\(c2) · \(ip2)")
                egress2OK = true
            }

            self.set("v6", .running)
            var v6OK = false
            let v6info = parseJSON(sh("curl -6 -s --max-time 5 https://ipinfo.io/json", timeout: 7))
            let v6c = v6info?["country"] as? String ?? ""
            if v6c.isEmpty {
                self.set("v6", .ok, "无 IPv6 出口")
                v6OK = true
            } else if blockedRegions.contains(v6c) {
                self.set("v6", .fail, "IPv6 泄漏至 \(v6c)！")
            } else {
                self.set("v6", .ok, "IPv6 也在 \(v6c)")
                v6OK = true
            }

            self.set("stun", .running)
            var stunOK = false
            let stunIP = sh("python3 $HOME/ClaudeGuard/stun_check.py", timeout: 12)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if stunIP.isEmpty {
                self.set("stun", .ok, "UDP 不通（无泄漏面）")
                stunOK = true
            } else if stunIP == cfIP {
                self.set("stun", .ok, "UDP 与出口一致")
                stunOK = true
            } else {
                let sc = sh("curl -s --max-time 5 https://ipinfo.io/\(stunIP)/country", timeout: 7)
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if blockedRegions.contains(sc) {
                    self.set("stun", .fail, "UDP 泄漏真实 IP \(stunIP)（\(sc)）！")
                } else {
                    self.set("stun", .warn, "UDP 出口 \(stunIP)（\(sc)）")
                    stunOK = true
                }
            }

            // 5) Anthropic
            self.set("api", .running)
            let apiOK = self.probeAnthropic()
            self.set("api", apiOK ? .ok : .fail, apiOK ? "地区已放行" : "被拒或不可达")

            // 6) 本机指纹（时区/语言）
            self.set("fingerprint", .running)
            let fp = self.probeFingerprint()
            self.set("fingerprint", fp.ok ? .ok : .warn, fp.detail)

            let pass = appsOK && tunOK && egressOK && egress2OK && v6OK && stunOK && apiOK
            self.logLine("检测完成: \(pass ? "PASS" : "FAILED") 出口=\(self.egressInfo)\(fp.ok ? "" : " ⚠️指纹:\(fp.detail)")")

            if pass {
                self.lastGuardPass = true
                self.setOverall(.pass)
                if openAfter { self.openClaude() }
            } else if autofix && clashInstalled {
                self.autoFix(openAfter: openAfter)
            } else {
                self.lastGuardPass = false
                self.setOverall(.fail)
            }
        }
    }

    // MARK: auto fix

    // 一键修复入口（手动按钮 / 直连恢复用）：修复后必转全量复检
    private func autoFix(openAfter: Bool) {
        DispatchQueue.main.async { self.busy = true; self.busyText = "自动修复中…" }
        logLine("开始自动修复")
        if autoFixOnce() {
            logLine("修复成功，转入全量复检")
            lastGuardPass = true
            DispatchQueue.main.async {
                self.busy = false; self.busyText = ""
                self.runFullCheck(autofix: false, openAfter: openAfter)
            }
        } else {
            logLine("修复失败")
            lastGuardPass = false
            setOverall(.fail)
            DispatchQueue.main.async { self.busy = false; self.busyText = "" }
        }
    }

    // 核心修复逻辑，同步返回是否成功（启动 Clash→开 TUN→切 SG 节点→出口+API 双验）
    // 不改 busy/overall，供实时守护重试循环与一键修复共用
    @discardableResult
    private func autoFixOnce() -> Bool {
        // 启动 Clash
        if parseJSON(coreAPI("/version")) == nil {
            DispatchQueue.main.async { self.busyText = "启动 Clash Verge…" }
            if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: clashBundleID) {
                NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
            }
            for _ in 0..<30 {
                Thread.sleep(forTimeInterval: 1)
                if parseJSON(coreAPI("/version")) != nil { break }
            }
            Thread.sleep(forTimeInterval: 2)
        }
        guard parseJSON(coreAPI("/version")) != nil else {
            logLine("修复失败：Clash 内核接口始终无响应")
            return false
        }

        // 开 TUN（并写回 Verge 配置防漂移）
        if tunEnabled() == false {
            DispatchQueue.main.async { self.busyText = "开启 TUN…" }
            _ = coreAPI("/configs", method: "PATCH", body: "{\"tun\":{\"enable\":true}}")
            Thread.sleep(forTimeInterval: 2)
            let on = tunEnabled() == true
            logLine("TUN: \(on ? "已开启" : "开启失败")")
            if on { syncVergeTun(true) }
        }

        // 选组
        var mode = (parseJSON(coreAPI("/configs"))?["mode"] as? String) ?? ""
        if mode == "direct" {
            _ = coreAPI("/configs", method: "PATCH", body: "{\"mode\":\"global\"}")
            mode = "global"
            logLine("代理模式: direct → global")
        }
        var group = "GLOBAL"
        if mode != "global", let proxies = parseJSON(coreAPI("/proxies"))?["proxies"] as? [String: [String: Any]] {
            let cands = proxies.filter { _, p in
                (p["type"] as? String) == "Selector" &&
                ((p["all"] as? [String]) ?? []).contains { n in sgKeywords.contains { n.contains($0) } }
            }.map { $0.key }
            group = cands.first { $0.contains("手动") } ?? cands.first { $0.contains("漏网") } ?? cands.first ?? "GLOBAL"
        }

        // 测速新加坡节点
        DispatchQueue.main.async { self.busyText = "测速新加坡节点…" }
        guard let proxies = parseJSON(coreAPI("/proxies"))?["proxies"] as? [String: [String: Any]],
              let all = proxies[group]?["all"] as? [String] else {
            logLine("修复失败：读取代理组 \(group) 失败")
            return false
        }
        let sgNodes = all.filter { n in sgKeywords.contains { n.contains($0) } }
        var ranked: [(Int, String)] = []
        let testURL = pctEncode("https://cp.cloudflare.com/generate_204")
        for node in sgNodes.prefix(8) {
            let resp = coreAPI("/proxies/\(pctEncode(node))/delay?timeout=3000&url=\(testURL)")
            if let d = parseJSON(resp)?["delay"] as? Int { ranked.append((d, node)) }
        }
        ranked.sort { $0.0 < $1.0 }
        logLine("可用 SG 节点: \(ranked.count)/\(sgNodes.count)")

        // 逐个切换并验证（出口非受限 + Anthropic 放行）
        for (delay, node) in ranked.prefix(3) {
            DispatchQueue.main.async { self.busyText = "切换 \(node)…" }
            _ = coreAPI("/proxies/\(pctEncode(group))", method: "PUT", body: "{\"name\":\"\(node)\"}")
            logLine("切换 [\(group)] → \(node) (\(delay)ms)")
            DispatchQueue.main.async { self.currentNode = node }
            Thread.sleep(forTimeInterval: 1.5)
            if tunEnabled() == true, let e = probeEgress(), !blockedRegions.contains(e.loc), probeAnthropic() {
                logLine("修复成功: \(node) 出口 \(e.loc) · \(e.ip)")
                return true
            }
        }
        logLine("修复失败：所有候选节点均未通过")
        return false
    }

    // MARK: direct mode

    func setDirectMode(_ on: Bool) {
        guard on != directMode else { return }
        DispatchQueue.main.async { self.directMode = on }
        q.async {
            if on {
                // 记住当前代理模式，断开 Claude 防裸奔，再切直连
                let cur = (parseJSON(coreAPI("/configs"))?["mode"] as? String) ?? "global"
                if cur != "direct" { self.savedClashMode = cur }
                let claudeRunning = !NSRunningApplication.runningApplications(withBundleIdentifier: claudeBundleID).isEmpty
                if claudeRunning {
                    self.cutClaude()
                    notifyUser("直连模式：已断开 Claude，守护暂停")
                }
                _ = coreAPI("/configs", method: "PATCH", body: "{\"mode\":\"direct\"}")
                _ = coreAPI("/configs", method: "PATCH", body: "{\"tun\":{\"enable\":false}}")
                self.syncVergeTun(false)
                self.logLine("进入直连模式（原模式 \(self.savedClashMode)，TUN 已关，守护暂停\(claudeRunning ? "，已断开 Claude" : "")）")
                self.setOverall(.direct)
            } else {
                _ = coreAPI("/configs", method: "PATCH", body: "{\"tun\":{\"enable\":true}}")
                self.syncVergeTun(true)
                _ = coreAPI("/configs", method: "PATCH", body: "{\"mode\":\"\(self.savedClashMode)\"}")
                self.logLine("退出直连模式，恢复 \(self.savedClashMode)，重新安检")
                Thread.sleep(forTimeInterval: 1.5)
                DispatchQueue.main.async { self.runFullCheck(autofix: true, openAfter: false) }
            }
        }
    }

    // MARK: realtime guard

    private func guardTick() {
        guard monitoring, !busy, !directMode else { return }
        q.async {
            let quick = self.quickPass()
            if quick {
                if !self.lastGuardPass {
                    self.logLine("网络已恢复")
                    notifyUser("✅ 网络已恢复，环境重新通过")
                }
                self.lastGuardPass = true
                if self.overall != .pass { self.setOverall(.pass) }
                return
            }
            // 复测一次，避免单次抖动误杀
            Thread.sleep(forTimeInterval: 1)
            if self.quickPass() { return }

            // 确认失守：立即强行断开 Claude（TUN 关闭 / 出口异常 / 被拒都算）
            self.lastGuardPass = false
            self.setOverall(.fail)
            let claudeRunning = !NSRunningApplication.runningApplications(withBundleIdentifier: claudeBundleID).isEmpty
            if claudeRunning {
                self.cutClaude()
                self.logLine("⚠️ 网络失守，已立即断开 Claude")
                notifyUser("⚠️ 网络失守（TUN 关闭/出口异常/被拒），已立即断开 Claude")
            } else {
                self.logLine("网络失守（Claude 未在运行）")
            }

            // 自动重试修复，最多 3 次；每次修复内部已含全量复检
            DispatchQueue.main.async { self.busy = true }
            for attempt in 1...3 {
                self.logLine("自动恢复尝试 \(attempt)/3…")
                DispatchQueue.main.async { self.busyText = "自动恢复 \(attempt)/3…" }
                if self.autoFixOnce() {
                    self.logLine("第 \(attempt) 次恢复成功")
                    self.lastGuardPass = true
                    self.setOverall(.pass)
                    DispatchQueue.main.async { self.busy = false; self.busyText = "" }
                    notifyUser("✅ 已自动恢复代理环境（第 \(attempt) 次）")
                    return
                }
                Thread.sleep(forTimeInterval: 2)
            }
            self.logLine("自动恢复失败：3 次尝试均未通过")
            notifyUser("❌ 自动恢复 3 次均失败，请手动检查 Clash / 网络")
            self.setOverall(.fail)
            DispatchQueue.main.async { self.busy = false; self.busyText = "" }
        }
    }

    private func quickPass() -> Bool {
        // TUN 必须开启：手动关 TUN → 立即判失守（这是实时守护的硬门槛）
        if tunEnabled() != true { return false }
        guard let e = probeEgress(), !blockedRegions.contains(e.loc) else { return false }
        DispatchQueue.main.async { self.egressInfo = "\(e.loc) · \(e.ip)" }
        return probeAnthropic()
    }

    private func cutClaude() {
        DispatchQueue.main.async {
            for a in NSRunningApplication.runningApplications(withBundleIdentifier: claudeBundleID) {
                a.terminate()
            }
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + 3) {
            for a in NSRunningApplication.runningApplications(withBundleIdentifier: claudeBundleID) {
                a.forceTerminate()
            }
        }
    }

    // MARK: actions

    func openClaude() {
        guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: claudeBundleID) else {
            logLine("打开失败：找不到 Claude.app")
            return
        }
        NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
        logLine("已打开 Claude")
    }
}

// MARK: - UI

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

            // PASS 态醒目安心横幅：让"我被保护着"一眼可见，不只是菜单栏一个绿点
            if model.overall == .pass && !model.directMode {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.shield.fill")
                        .foregroundColor(Color(red: 0.16, green: 0.66, blue: 0.36))
                        .font(.system(size: 16, weight: .bold))
                    VStack(alignment: .leading, spacing: 1) {
                        Text("环境安全，正在守护")
                            .font(.system(size: 12.5, weight: .semibold))
                        Text("全部 \(model.checks.count) 项检查通过 · 出口 \(model.egressInfo)")
                            .font(.system(size: 10.5)).foregroundColor(.secondary)
                            .lineLimit(1).truncationMode(.middle)
                    }
                    Spacer()
                }
                .padding(.horizontal, 10).padding(.vertical, 8)
                .background(RoundedRectangle(cornerRadius: 10)
                    .fill(Color(red: 0.16, green: 0.66, blue: 0.36).opacity(0.12)))
            }

            // 模式切换：守护（代理+安检）⇄ 直连（不用 Claude 时）
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
                    Text("节点 \(model.currentNode)").font(.system(size: 11)).foregroundColor(.secondary)
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
                        Button(action: { model.runFullCheck(autofix: true, openAfter: true) }) {
                            Label("一键修复并打开", systemImage: "wand.and.stars")
                                .frame(maxWidth: .infinity)
                        }
                        .controlSize(.large)
                        .buttonStyle(.borderedProminent)
                        .tint(.orange)
                        .disabled(model.busy)
                    }
                    Button(action: { model.runFullCheck(autofix: true, openAfter: false) }) {
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

// MARK: - App bootstrap

final class AppDelegate: NSObject, NSApplicationDelegate, NSUserNotificationCenterDelegate {
    var statusItem: NSStatusItem!
    var panel: NSPanel!
    var clickMonitor: Any?
    let model = GuardModel()

    // 菜单栏原生小图标：盾形 SF Symbol，按状态着色（模板色彩，深浅色菜单栏都自然）
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

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem.button?.image = statusImage(for: .checking)
        statusItem.button?.action = #selector(togglePopover)
        statusItem.button?.target = self

        // 手动定位面板：不用 NSPopover（定位不可靠），按屏幕坐标钉在图标正下方
        let host = NSHostingController(rootView: GuardView(model: model))
        host.safeAreaRegions = []   // 去掉透明标题栏占位，内容顶到面板最上沿
        panel = NSPanel(contentViewController: host)
        panel.styleMask = [.titled, .fullSizeContentView, .nonactivatingPanel]
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        panel.isMovable = false
        panel.level = .statusBar
        panel.isReleasedWhenClosed = false
        panel.hidesOnDeactivate = false
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        for b: NSWindow.ButtonType in [.closeButton, .miniaturizeButton, .zoomButton] {
            panel.standardWindowButton(b)?.isHidden = true
        }

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
        }
        model.logLine("=== ClaudeGuard 启动 ===")
        NSUserNotificationCenter.default.delegate = self
        model.start()
        // 启动即弹面板：让用户直接看到全部检测状态，不只是菜单栏一个绿点
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { self.togglePopover() }
    }

    // 即便 app 在前台也强制弹出通知（否则守护提醒可能被系统吞掉）
    func userNotificationCenter(_ center: NSUserNotificationCenter,
                                shouldPresent notification: NSUserNotification) -> Bool {
        return true
    }

    // 点击通知 → 弹出守护面板（旧版会跳去 osascript 的 transcript）
    func userNotificationCenter(_ center: NSUserNotificationCenter,
                                didActivate notification: NSUserNotification) {
        NSApp.activate(ignoringOtherApps: true)
        if !panel.isVisible { togglePopover() }
    }

    func hidePanel() {
        panel.orderOut(nil)
        if let m = clickMonitor { NSEvent.removeMonitor(m); clickMonitor = nil }
    }

    @objc func togglePopover() {
        if panel.isVisible { hidePanel(); return }
        guard let btnWindow = statusItem.button?.window,
              let screen = btnWindow.screen ?? NSScreen.main else { return }
        panel.layoutIfNeeded()
        let icon = btnWindow.frame            // 菜单栏图标的屏幕坐标
        let size = panel.frame.size
        var x = icon.midX - size.width / 2
        let vis = screen.visibleFrame
        x = min(max(x, vis.minX + 8), vis.maxX - size.width - 8)
        let y = icon.minY - size.height - 6   // 图标下边缘再往下 6px
        panel.setFrameOrigin(NSPoint(x: x, y: y))
        panel.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        // 点面板外任意处自动收起
        clickMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
            self?.hidePanel()
        }
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
