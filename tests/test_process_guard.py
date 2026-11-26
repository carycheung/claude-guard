"""Exercise the production process guard using only children owned by these tests."""
import json
import plistlib
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest


DRIVER = r'''
let args = CommandLine.arguments
let home = args[2]
let root = home + "/Applications/Claude.app/Contents/"
var result: [String: Any] = [:]
switch args[1] {
case "paths":
    result["default"] = args.dropFirst(3).map { isManagedClaudeExecutablePath($0, homeDir: home) }
    result["isolated"] = args.dropFirst(3).map {
        isManagedClaudeExecutablePath($0, homeDir: home, appContentsRoots: [root])
    }
case "resolve":
    var fallbackCalls = 0
    let path = resolveRealClaudeAppPath(homeDir: home, installedPath: home + "/Applications/Claude.app") {
        fallbackCalls += 1
        return home + "/registered/Claude.app"
    }
    result = ["path": path ?? "", "fallbackCalls": fallbackCalls]
case "gate":
    let config = parseJSON(args[3])
    var calls: [String] = []
    let failure = localTunnelGateFailure(readConfig: { calls.append("config"); return config },
        routeInterface: { calls.append("route"); return args[4] },
        dnsLookup: { calls.append("dns"); return args[5] })
    result = ["failure": failure ?? "", "calls": calls]
case "verified-gate":
    let spec = parseJSON(args[3])!
    let cfgSteps = spec["configs"] as! [[String: Any]]
    let routes = spec["routes"] as! [String]
    let dnsSteps = spec["dns"] as! [[String: Any]]
    var cfgIdx = 0, routeIdx = 0, dnsIdx = 0
    let failure = verifiedLocalTunnelGateFailure(
        fetchConfig: { _ in
            let item = cfgSteps[min(cfgIdx, cfgSteps.count - 1)]
            cfgIdx += 1
            return (item["cfg"] as? [String: Any], item["timedOut"] as? Bool ?? false)
        },
        checkRoute: {
            let r = routes[min(routeIdx, routes.count - 1)]
            routeIdx += 1
            return r.isEmpty ? nil : r
        },
        resolveDNS: { _ in
            let item = dnsSteps[min(dnsIdx, dnsSteps.count - 1)]
            dnsIdx += 1
            return (item["ip"] as? String, item["timedOut"] as? Bool ?? false)
        }
    )
    result = ["failure": failure ?? "", "cfgCalls": cfgIdx, "routeCalls": routeIdx, "dnsCalls": dnsIdx]
case "path-filter":
    let spec = parseJSON(args[3])!
    let ignore = shouldIgnorePathEvent(
        wake: spec["wake"] as? Bool ?? false,
        gateFailure: spec["failure"] as? String,
        lastPass: spec["lastPass"] as? Bool ?? false,
        newSignature: spec["newSig"] as? String ?? "",
        lastSignature: spec["lastSig"] as? String ?? "",
        inFlightSignature: spec["inFlightSig"] as? String
    )
    let nodeInfo = resolveActiveNodeInfo(
        config: spec["config"] as? [String: Any],
        proxiesRoot: spec["proxies"] as? [String: Any]
    )
    result = ["ignore": ignore, "nodeDisplay": nodeInfo.display, "nodeSig": nodeInfo.signature]
case "remote-resilience":
    let spec = parseJSON(args[3])!
    let tunnelOK = spec["tunnelOK"] as? Bool ?? true
    let apiSteps = spec["apiSteps"] as? [[String: Any]] ?? []
    var apiCalls = 0
    let apiOK = probeAnthropicResilient(
        maxTransientRetries: 2,
        isLocalTunnelIntact: { tunnelOK },
        performAttempt: { _ in
            let item = apiSteps[min(apiCalls, max(0, apiSteps.count - 1))]
            apiCalls += 1
            return HTTPProbeResult(
                statusCode: item["code"] as? Int ?? 0,
                body: item["body"] as? String ?? ""
            )
        }
    )
    let v6Steps = spec["v6Steps"] as? [[String: Any]] ?? []
    var v6Calls = 0
    let v6Res = probeIPv6CloudflareResilient(
        isLocalTunnelIntact: { tunnelOK },
        performAttempt: {
            let item = v6Steps[min(v6Calls, max(0, v6Steps.count - 1))]
            v6Calls += 1
            if let loc = item["loc"] as? String, !loc.isEmpty {
                return (loc, item["ip"] as? String ?? "")
            }
            return nil
        }
    )
    result = [
        "apiOK": apiOK,
        "apiCalls": apiCalls,
        "v6Loc": v6Res?.loc ?? "",
        "v6Calls": v6Calls
    ]
case "app":
    var alive = true
    var pids: [pid_t] = []
    var events: [String] = []
    result["stopped"] = terminateManagedClaude(gracePeriod: 0.01, timeout: 0.5,
        listPIDs: { pids }, hasRunningApp: { alive },
        requestAppTerminate: { events.append("request") },
        forceAppTerminate: {
            events.append("force")
            alive = false
            pids = [101]
        },
        sendSignal: { pid, sig in
            precondition(sig == SIGKILL)
            events.append("kill \(pid)")
            pids = pid == 101 ? [102] : []
        })
    result["events"] = events
case "empty":
    result["stopped"] = terminateManagedClaude(gracePeriod: 1, timeout: 3, listPIDs: { [] },
        requestAppTerminate: { fatalError("unexpected app termination") },
        forceAppTerminate: { fatalError("unexpected forced termination") },
        sendSignal: { _, _ in fatalError("unexpected signal") })
case "stop", "noop", "preflight", "no-repair", "timeout", "sleep", "version":
    let child = pid_t(args[3])!
    let grace = 0.2
    func scan() -> [pid_t] {
        listManagedClaudePIDs(homeDir: home, appContentsRoots: [root])
    }
    let initial = scan()
    precondition(initial == [child], "isolated PID scan: \(initial), expected \(child)")
    let excluded = listManagedClaudePIDs(selfPID: child, homeDir: home, appContentsRoots: [root])
    precondition(excluded.isEmpty)
    let otherUID = listManagedClaudePIDs(currentUID: getuid() ^ 1, homeDir: home, appContentsRoots: [root])
    precondition(otherUID.isEmpty)

    var events: [String] = []
    var signalTimes: [Double] = []
    let start = ProcessInfo.processInfo.systemUptime
    func cut() -> Bool {
        terminateManagedClaude(gracePeriod: grace, timeout: 0.6, listPIDs: {
            let pids = scan()
            precondition(pids.allSatisfy { $0 == child })
            if pids.isEmpty { events.append("exited") }
            return pids
        }, hasRunningApp: { args[1] == "sleep" && !scan().isEmpty }, requestAppTerminate: {
            performOnMain {
                precondition(Thread.isMainThread)
                events.append("appRequest")
            }
        }, forceAppTerminate: {
            guard args[1] == "sleep" else { return }
            performOnMain {
                precondition(Thread.isMainThread)
                events.append("appForce")
            }
        }, sendSignal: { pid, sig in
            precondition(pid == child && pid > 1)
            events.append(sig == SIGTERM ? "TERM" : "KILL")
            signalTimes.append(ProcessInfo.processInfo.systemUptime - start)
            if !["noop", "timeout"].contains(args[1]) { precondition(Darwin.kill(pid, sig) == 0) }
        })
    }
    let stopped: Bool
    if ["preflight", "no-repair", "timeout", "version"].contains(args[1]) {
        var enabled = args[1] == "version"
        func gate() -> String? {
            localTunnelGateFailure(readConfig: { ["tun": ["enable": enabled, "inet6-address": ["fd00::1/126"]]] },
                routeInterface: { "utun3" }, dnsLookup: { "ip_address: 198.18.0.1" })
        }
        let local = checkLocalProtection(tunnelFailure: gate, readVersion: { args[1] == "version" ? nil : "1" },
            cutIfRunning: { _ in scan().isEmpty || cut() }, repair: {
                events.append("repair")
                enabled = args[1] != "no-repair"
            })
        if local.canProbe { events.append("slowProbe") }
        stopped = local.stopped
    } else {
        stopped = cut()
        if stopped && args[1] != "sleep" { events.append("disableTun") }
    }
    result = ["stopped": stopped, "events": events, "signalTimes": signalTimes,
              "elapsed": ProcessInfo.processInfo.systemUptime - start, "remaining": scan()]
default:
    fatalError("unknown test")
}
print(String(decoding: try! JSONSerialization.data(withJSONObject: result), as: UTF8.self))
'''


class ProcessGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="cg-process-", dir="/tmp")
        cls.addClassCleanup(cls.workspace.cleanup)
        cls.root = Path(cls.workspace.name).resolve()
        source = (Path(__file__).resolve().parents[1] / "main.swift").read_text()
        core, marker, _ = source.partition("// app 内部发通知：")
        if not marker:
            raise AssertionError("missing headless test boundary")
        driver = cls.root / "main.swift"
        driver.write_text(core + DRIVER)
        cls.driver = cls.root / "guard-test"
        subprocess.run(["xcrun", "swiftc", "-module-cache-path", str(cls.root / "modules"), str(driver), "-o", str(cls.driver)], check=True)
        # A readiness byte proves the executable and its SIGTERM disposition are in place.
        child = cls.root / "child.c"
        child.write_text("""
#include <signal.h>
#include <unistd.h>
int main(int argc, char **argv) {
    signal(SIGTERM, argc > 1 ? SIG_IGN : SIG_DFL);
    if (write(STDOUT_FILENO, "R", 1) != 1) return 1;
    for (;;) pause();
}
""")
        cls.child = cls.root / "child"
        subprocess.run(["xcrun", "clang", str(child), "-o", str(cls.child)], check=True)

    def setUp(self):
        workspace = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(workspace.cleanup)
        self.home = Path(workspace.name) / "fakeHome"

    def run_guard(self, operation, *args):
        run = subprocess.run([self.driver, operation, self.home, *args], check=True,
                             capture_output=True, text=True, timeout=10)
        return json.loads(run.stdout)

    def test_executable_path_allowlist(self):
        default = "/Applications/Claude.app/Contents"
        hidden = self.home / "Library/ClaudeGuard/Claude.app/Contents"
        custom = self.home / "Applications/Claude.app/Contents"
        cli = self.home / "Library/Application Support/Claude/claude-code/2.1.330/hash/claude.app/Contents/MacOS"
        versions = self.home / ".local/share/claude/versions"
        both = [cli / "claude", versions / "2.1.276"]
        standard = [f"{default}/MacOS/Claude", f"{default}/Helpers/disclaimer",
                    f"{default}/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper",
                    hidden / "MacOS/Claude", hidden / "Helpers/disclaimer",
                    "/opt/homebrew/Caskroom/claude-code/2.1/claude",
                    "/usr/local/Caskroom/claude-code/2.1/claude"]
        isolated = [custom / "MacOS/Claude"]
        neither = [f"{default}/MacOS/ClaudeShim", hidden / "MacOS/ClaudeShim", custom / "MacOS/ClaudeShim",
                   self.home / "Applications/ClaudeGuard.app/Contents/MacOS/ClaudeGuard",
                   hidden / "Frameworks/ClaudeGuard.app/Contents/MacOS/ClaudeGuard",
                   f"{default}Backup/MacOS/Claude", cli / "claude-hunter",
                   self.home / "Obsidian Vault/claude code/bin/claude", "/usr/local/bin/agy", "/usr/bin/grep",
                   versions / ".partial", versions / "2/bin/claude", str(versions) + "/",
                   str(versions) + "-old/2", f"{default}/../Other", "/opt/homebrew/Caskroom/other/claude"]
        paths = both + standard + isolated + neither
        found = self.run_guard("paths", *paths)
        for index, path in enumerate(paths):
            with self.subTest(path=path):
                self.assertEqual(found["default"][index], path in both + standard)
                self.assertEqual(found["isolated"][index], path in both + isolated)

    def test_launchagent_plist(self):
        script = Path(__file__).resolve().parents[1] / "install-launchagent.sh"
        plist = self.root / "test-launchagent.plist"
        binary = str(self.home / "Apps & Tools/ClaudeGuard.app/Contents/MacOS/ClaudeGuard")
        subprocess.run(["/bin/bash", "-c", 'source "$1"; BIN="$2"; write_plist "$3"',
                        "render-plist", script, binary, plist], check=True)
        self.assertEqual(plistlib.loads(plist.read_bytes()), {
            "Label": "com.claudeguard.app",
            "ProgramArguments": [binary],
            "RunAtLoad": True,
            "KeepAlive": {"SuccessfulExit": False},
            "ThrottleInterval": 2,
        })

    def test_shipit_paths(self):
        name = "com.anthropic.claudefordesktop.ShipIt"
        cache = self.home / "Library/Caches" / name / "update"
        suffix = "Claude.app/Contents/MacOS/Claude"
        tmp = f"/var/folders/ab/hash/T/{name}.xy12"
        good = [str(cache / suffix), f"{tmp}/{suffix}", f"/private{tmp}/{suffix}"]
        bad = [str(cache / suffix) + "Shim", f"{tmp}/{suffix}Shim",
               f"{tmp}/Other.app/Contents/MacOS/Claude", f"/other{tmp}/{suffix}",
               f"/var/folders/{name}Backup.xy/{suffix}", f"/var/folders/{name}./{suffix}",
               f"/var/folders/{suffix}/{name}.xy/helper", str(cache).replace(name, name + "Old") + "/" + suffix]
        found = self.run_guard("paths", *(good + bad))
        self.assertEqual(found["default"], [True] * len(good) + [False] * len(bad))
        self.assertEqual(found["isolated"], [True, False, False] + [False] * len(bad))

    def test_real_app_resolution(self):
        hidden = self.home / "Library/ClaudeGuard/Claude.app"
        original = self.home / "Applications/Claude.app"
        registered = self.home / "registered/Claude.app"

        def bundle(path, shim=False):
            info = path / "Contents/Info.plist"
            info.parent.mkdir(parents=True, exist_ok=True)
            info.write_bytes(plistlib.dumps({"ClaudeGuardShim": shim}))

        def expect(path, calls):
            self.assertEqual(self.run_guard("resolve"), {"path": str(path), "fallbackCalls": calls})

        bundle(original)
        expect(original, 0)
        bundle(hidden)
        expect(hidden, 0)
        bundle(original, shim=True)
        expect(hidden, 0)
        bundle(hidden, shim=True)
        expect("", 1)
        bundle(registered)
        expect(registered, 1)
        bundle(registered, shim=True)
        expect("", 1)

    def test_read_only_gate_short_circuits_and_uses_first_ipv4(self):
        good = {"enable": True, "inet6-address": ["fd00::1/126"]}
        fake_ip = "ipv6_address: fd00::1\nip_address: 198.18.0.9"
        for tun, route, dns, reason, calls in [
            ({}, "", "", "代理内核接口不可达，TUN 状态未知", ["config"]),
            ({"enable": False}, "", "", "TUN 已关闭", ["config"]),
            ({"enable": True}, "", "", "TUN 未接管 IPv6 路由", ["config"]),
            (good, "en0", fake_ip, "TUN 未接管 IPv6 路由", ["config", "route"]),
            (good, "utun1", "ip_address: 1.2.3.4\n" + fake_ip,
             "TUN 已开但系统 DNS 未被 Fake-IP 接管", ["config", "route", "dns"]),
            (good, "utun1", fake_ip, "", ["config", "route", "dns"]),
        ]:
            with self.subTest(tun=tun, route=route, dns=dns):
                self.assertEqual(self.run_guard("gate", json.dumps({"tun": tun}), route, dns),
                                 {"failure": reason, "calls": calls})

    def test_tun_off_child_exits_before_repair_and_slow_probe(self):
        result = self.run_child("preflight")
        self.assertEqual(result["returncode"], -signal.SIGTERM)
        self.assertEqual(result["events"], ["TERM", "exited", "repair", "slowProbe"])

    def test_missing_version_cuts_and_skips_slow_probe(self):
        result = self.run_child("version")
        self.assertEqual(result["events"], ["TERM", "exited"])

    def test_unrepaired_tunnel_skips_slow_probe(self):
        result = self.run_child("no-repair")
        self.assertTrue(result["stopped"])
        self.assertEqual(result["events"], ["TERM", "exited", "repair"])

    def test_preflight_timeout_blocks_repair_and_probe(self):
        result = self.run_child("timeout")
        self.assertFalse(result["stopped"])
        self.assertNotIn("repair", result["events"])
        self.assertNotIn("slowProbe", result["events"])

    def test_main_thread_sleep_can_request_and_force_exit(self):
        result = self.run_child("sleep", ignore_term=True)
        self.assertEqual(result["returncode"], -signal.SIGKILL)
        self.assertEqual(result["events"], ["appRequest", "TERM", "appForce", "KILL", "exited"])

    def run_child(self, operation, ignore_term=False):
        executable = self.home / ".local/share/claude/versions/9.9.9"
        executable.parent.mkdir(parents=True)
        shutil.copy2(self.child, executable)
        args = [executable, "ignore"] if ignore_term else [executable]
        with subprocess.Popen(args, stdout=subprocess.PIPE) as child:
            try:
                self.assertEqual(child.stdout.read(1), b"R")
                result = self.run_guard(operation, str(child.pid))
                if result["stopped"]:
                    result["returncode"] = child.wait(timeout=1)
                else:
                    self.assertIsNone(child.poll())
                    self.assertEqual(result["remaining"], [child.pid])
                return result
            finally:
                if child.poll() is None:
                    child.kill()

    def test_term_exit_precedes_disable_tun(self):
        result = self.run_child("stop")
        self.assertTrue(result["stopped"])
        self.assertEqual(result["returncode"], -signal.SIGTERM)
        self.assertEqual(result["events"], ["TERM", "exited", "disableTun"])

    def test_term_ignored_escalates_after_grace(self):
        result = self.run_child("stop", ignore_term=True)
        self.assertTrue(result["stopped"])
        self.assertEqual(result["returncode"], -signal.SIGKILL)
        self.assertEqual(result["events"][0], "TERM")
        self.assertEqual(result["events"][-2:], ["exited", "disableTun"])
        self.assertGreaterEqual(result["signalTimes"][result["events"].index("KILL")], 0.2)

    def test_timeout_keeps_tun_enabled(self):
        result = self.run_child("noop")
        self.assertFalse(result["stopped"])
        self.assertEqual(result["events"].count("disableTun"), 0)
        self.assertIn("KILL", result["events"])
        self.assertGreaterEqual(result["elapsed"], 0.6)

    def test_app_only_and_late_children(self):
        result = self.run_guard("app")
        self.assertTrue(result["stopped"])
        self.assertEqual(result["events"], ["request", "force", "kill 101", "kill 102"])

    def test_already_clear_needs_no_signals(self):
        self.assertTrue(self.run_guard("empty")["stopped"])

    def test_local_gate_rejects_direct_mode_even_when_tun_enabled(self):
        cfg = {"mode": "direct", "tun": {"enable": True, "inet6-address": ["fd00::1/126"]}}
        res = self.run_guard("gate", json.dumps(cfg), "utun4", "ip_address: 198.18.0.9")
        self.assertEqual(res["failure"], "代理处于直连模式，未走隧道")
        self.assertEqual(res["calls"], ["config"])

    def test_swap_stall_retries_only_when_kernel_utun_intact(self):
        good_cfg = {"mode": "rule", "tun": {"enable": True, "inet6-address": ["fd00::1/126"]}}
        cases = [
            # 1) Transient config swap timeout while kernel utun route intact -> retries once and passes
            (
                {"configs": [{"timedOut": True}, {"cfg": good_cfg, "timedOut": False}],
                 "routes": ["utun4", "utun4"],
                 "dns": [{"ip": "198.18.0.26", "timedOut": False}]},
                "", 2, 1,
            ),
            # 2) Transient DNS swap timeout while kernel utun route intact -> retries once and passes
            (
                {"configs": [{"cfg": good_cfg, "timedOut": False}],
                 "routes": ["utun4", "utun4"],
                 "dns": [{"timedOut": True}, {"ip": "198.18.0.26", "timedOut": False}]},
                "", 1, 2,
            ),
            # 3) Persistent DNS timeout -> still fails closed after single retry
            (
                {"configs": [{"cfg": good_cfg, "timedOut": False}],
                 "routes": ["utun4", "utun4"],
                 "dns": [{"timedOut": True}, {"timedOut": True}]},
                "TUN 已开但系统 DNS 未被 Fake-IP 接管", 1, 2,
            ),
            # 4) Real non-Fake-IP DNS leak (timedOut=False) -> zero retries, immediate failure
            (
                {"configs": [{"cfg": good_cfg, "timedOut": False}],
                 "routes": ["utun4"],
                 "dns": [{"ip": "1.2.3.4", "timedOut": False}, {"ip": "198.18.0.26", "timedOut": False}]},
                "TUN 已开但系统 DNS 未被 Fake-IP 接管", 1, 1,
            ),
            # 5) Config timeout when kernel route dropped to en0 -> zero retries, immediate failure
            (
                {"configs": [{"timedOut": True}, {"cfg": good_cfg, "timedOut": False}],
                 "routes": ["en0"],
                 "dns": [{"ip": "198.18.0.26", "timedOut": False}]},
                "代理内核接口不可达，TUN 状态未知", 1, 0,
            ),
        ]
        for spec, expected_failure, expected_cfg_calls, expected_dns_calls in cases:
            with self.subTest(spec=spec):
                out = self.run_guard("verified-gate", json.dumps(spec))
                self.assertEqual(out["failure"], expected_failure)
                self.assertEqual(out["cfgCalls"], expected_cfg_calls)
                self.assertEqual(out["dnsCalls"], expected_dns_calls)

    def test_path_event_dedup_ignores_simulator_noise_and_tracks_node_chain(self):
        proxies = {
            "proxies": {
                "PROXY": {"type": "Selector", "now": "AWS-SG-Auto"},
                "AWS-SG-Auto": {"type": "Fallback", "now": "AWS-SG-Hy2"},
            }
        }
        sig = "utun4|utun4|en0|svc|192.168.1.1|114.114.114.114|en0=192.168.1.5,utun4=198.18.0.1|rule|PROXY->AWS-SG-Auto->AWS-SG-Hy2"

        # Spurious Simulator / AWDL callback with identical signature while PASS -> ignored
        same = self.run_guard("path-filter", json.dumps({
            "wake": False, "lastPass": True, "newSig": sig, "lastSig": sig,
            "config": {"mode": "rule"}, "proxies": proxies,
        }))
        self.assertTrue(same["ignore"])
        self.assertEqual(same["nodeDisplay"], "AWS-SG-Auto → AWS-SG-Hy2")
        self.assertEqual(same["nodeSig"], "rule|PROXY->AWS-SG-Auto->AWS-SG-Hy2")

        # Duplicate callback matching in-flight check signature -> ignored (no generation livelock)
        inflight = self.run_guard("path-filter", json.dumps({
            "wake": False, "lastPass": False, "newSig": sig, "lastSig": "", "inFlightSig": sig,
        }))
        self.assertTrue(inflight["ignore"])

        # Wake event -> never ignored even if signature matches
        wake = self.run_guard("path-filter", json.dumps({
            "wake": True, "lastPass": True, "newSig": sig, "lastSig": sig,
        }))
        self.assertFalse(wake["ignore"])

        # Real node or interface change -> never ignored
        changed = self.run_guard("path-filter", json.dumps({
            "wake": False, "lastPass": True, "newSig": sig + "-changed", "lastSig": sig,
        }))
        self.assertFalse(changed["ignore"])

    def test_local_gate_enforces_configured_utun_device_and_rejects_foreign_utun(self):
        cfg_utun4 = {
            "mode": "rule",
            "tun": {"enable": True, "device": "utun4", "inet6-address": ["fdfe:dcba:9876::1/126"]},
        }
        # Matching mihomo utun4 -> passes
        ok = self.run_guard("gate", json.dumps(cfg_utun4), "utun4", "ip_address: 198.18.0.2")
        self.assertEqual(ok["failure"], "")

        # Foreign VPN / system utun7 when mihomo expects utun4 -> rejected
        foreign = self.run_guard("gate", json.dumps(cfg_utun4), "utun7", "ip_address: 198.18.0.2")
        self.assertEqual(foreign["failure"], "TUN 未接管 IPv6 路由")
        self.assertEqual(foreign["calls"], ["config", "route"])

        # Split IPv6/IPv4 across different utun devices -> rejected
        split = self.run_guard("gate", json.dumps(cfg_utun4), "utun4/utun7", "ip_address: 198.18.0.2")
        self.assertEqual(split["failure"], "TUN 未接管 IPv6 路由")

    def test_anthropic_and_ipv6_resilience_retries_transient_timeout_not_geoblock(self):
        auth_err = '{"type":"error","error":{"type":"authentication_error","message":"x-api-key header is required"}}'
        geo_err = '{"error":{"type":"forbidden","message":"Request not allowed"}}'

        # 1) Transient timeout (23:46:16 scenario) while local utun intact -> retries and passes
        transient_ok = self.run_guard("remote-resilience", json.dumps({
            "tunnelOK": True,
            "apiSteps": [{"code": 0, "body": ""}, {"code": 401, "body": auth_err}],
            "v6Steps": [{}, {"loc": "SG", "ip": "2606::1"}],
        }))
        self.assertTrue(transient_ok["apiOK"])
        self.assertEqual(transient_ok["apiCalls"], 2)
        self.assertEqual(transient_ok["v6Loc"], "SG")
        self.assertEqual(transient_ok["v6Calls"], 2)

        # 2) Explicit HTTP 403 geo-block or CN IPv6 leak -> ZERO retries, immediate fail
        blocked = self.run_guard("remote-resilience", json.dumps({
            "tunnelOK": True,
            "apiSteps": [{"code": 403, "body": geo_err}, {"code": 401, "body": auth_err}],
            "v6Steps": [{"loc": "HK", "ip": "2400::1"}, {"loc": "SG", "ip": "2606::1"}],
        }))
        self.assertFalse(blocked["apiOK"])
        self.assertEqual(blocked["apiCalls"], 1)
        self.assertEqual(blocked["v6Loc"], "HK")
        self.assertEqual(blocked["v6Calls"], 1)

        # 3) Timeout when local utun dropped -> ZERO retries, immediate fail
        dropped = self.run_guard("remote-resilience", json.dumps({
            "tunnelOK": False,
            "apiSteps": [{"code": 0, "body": ""}, {"code": 401, "body": auth_err}],
            "v6Steps": [{}, {"loc": "SG", "ip": "2606::1"}],
        }))
        self.assertFalse(dropped["apiOK"])
        self.assertEqual(dropped["apiCalls"], 1)
        self.assertEqual(dropped["v6Loc"], "")
        self.assertEqual(dropped["v6Calls"], 1)

    def test_lazy_panel_first_open_and_hidden_state_transitions_match_fitting_size(self):
        source = (Path(__file__).resolve().parents[1] / "main.swift").read_text()
        ui_head, marker, _ = source.partition('if CommandLine.arguments.contains("--help")')
        self.assertTrue(marker)
        probe_swift = self.root / "panel_probe.swift"
        probe_bin = self.root / "panel-probe"
        probe_swift.write_text(ui_head + '''
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let d = AppDelegate()
d.model.checks = [
    CheckItem(id: "claudeApp", title: "Claude 应用", state: .ok, detail: "Claude.app"),
    CheckItem(id: "clashApp", title: "Clash Verge 应用", state: .ok, detail: ""),
    CheckItem(id: "core", title: "Clash 内核接口", state: .ok, detail: "mihomo v1.19"),
    CheckItem(id: "tun", title: "TUN 模式", state: .ok, detail: "已开启"),
    CheckItem(id: "egress", title: "出口 · Cloudflare", state: .ok, detail: "SG · 1.2.3.4"),
    CheckItem(id: "egress2", title: "出口复核 · ipinfo", state: .ok, detail: "SG · 1.2.3.4"),
    CheckItem(id: "v6", title: "IPv6 泄漏", state: .ok, detail: "utun4 -> SG"),
    CheckItem(id: "stun", title: "WebRTC/UDP 泄漏", state: .ok, detail: "一致"),
    CheckItem(id: "api", title: "Anthropic 放行", state: .ok, detail: "地区已放行"),
    CheckItem(id: "fingerprint", title: "指纹 · 时区/语言", state: .ok, detail: "en-SG")
]
d.model.overall = .pass
let s1 = d.syncPanelContentSize()
let f1 = d.hostController!.view.fittingSize

d.model.directMode = true
let s2 = d.syncPanelContentSize()
let f2 = d.hostController!.view.fittingSize

d.model.directMode = false
d.model.busy = true
d.model.busyText = "自动修复中…"
let s3 = d.syncPanelContentSize()
let f3 = d.hostController!.view.fittingSize

let out: [String: Any] = [
    "s1": [s1.width, s1.height], "f1": [f1.width, f1.height],
    "s2": [s2.width, s2.height], "f2": [f2.width, f2.height],
    "s3": [s3.width, s3.height], "f3": [f3.width, f3.height]
]
print(String(data: try! JSONSerialization.data(withJSONObject: out), encoding: .utf8)!)
''')
        subprocess.run(
            ["xcrun", "swiftc", "-module-cache-path", str(self.root / "modules"),
             str(probe_swift), "-o", str(probe_bin), "-framework", "AppKit", "-framework", "SwiftUI"],
            check=True, capture_output=True
        )
        run = subprocess.run([str(probe_bin)], check=True, capture_output=True, text=True, timeout=10)
        sizes = json.loads(run.stdout)
        self.assertEqual(sizes["s1"], sizes["f1"])
        self.assertEqual(sizes["s2"], sizes["f2"])
        self.assertEqual(sizes["s3"], sizes["f3"])
        self.assertEqual(sizes["s1"][0], 320.0)
        self.assertGreater(sizes["s1"][1], 500.0)
        self.assertLess(sizes["s2"][1], sizes["s1"][1])
        self.assertGreater(sizes["s3"][1], sizes["s1"][1])
