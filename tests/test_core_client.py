"""Regression checks using temporary Unix sockets; never change the real proxy."""
import http.server
import json
from pathlib import Path
import socket
import socketserver
import subprocess
import tempfile
import threading
import unittest


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class CoreClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="cg-test-", dir="/tmp")
        cls.root = Path(cls.workspace.name)
        source = (Path(__file__).resolve().parents[1] / "main.swift").read_text()
        # Compile the production helper, without the app bootstrap or UI.
        source = source.split("// app 内部发通知：", 1)[0]
        source += '''
let client = CoreClient(candidates: Array(CommandLine.arguments.dropFirst(2)))
let operation = CommandLine.arguments[1]
if operation == "timeout-meta" {
    let timedClient = CoreClient(candidates: Array(CommandLine.arguments.dropFirst(2)), requestTimeout: 0.25)
    let start = ProcessInfo.processInfo.systemUptime
    let meta = timedClient.callWithStatus("/configs")
    let elapsed = ProcessInfo.processInfo.systemUptime - start
    let out: [String: Any] = ["body": meta.body ?? NSNull(), "timedOut": meta.timedOut, "elapsed": elapsed]
    print(String(data: try! JSONSerialization.data(withJSONObject: out), encoding: .utf8)!)
    exit(0)
}
let first = client.call("/configs")
var result: [String: Any] = ["first": parseJSON(first) ?? [:]]
if operation == "write" || operation == "drop-write" {
    result["write"] = client.call("/configs", method: "PATCH", body: "{\\"name\\":\\"a'b $()\\"}")
} else if operation == "reconnect" {
    result["second"] = parseJSON(client.call("/configs")) ?? [:]
}
result["socket"] = client.socket ?? ""
print(String(data: try! JSONSerialization.data(withJSONObject: result), encoding: .utf8)!)
'''
        swift = cls.root / "main.swift"
        swift.write_text(source)
        cls.binary = cls.root / "core-test"
        subprocess.run(["xcrun", "swiftc", "-module-cache-path", str(cls.root / "modules"), str(swift), "-o", str(cls.binary)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=self.root)
        self.root_case = Path(self.directory.name)
        self.servers = []

    def tearDown(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        self.directory.cleanup()

    def server(self, name, config, drop_write=False, fail_after_first=False):
        path = str(self.root_case / name)
        calls = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                calls.append(("GET", self.path))
                if fail_after_first and len(calls) > 1:
                    self.send_error(503)
                    return
                body = json.dumps(config).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_PATCH(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                calls.append(("PATCH", json.loads(body)))
                if drop_write:
                    self.close_connection = True
                    return
                self.send_response(204)
                self.end_headers()

        server = UnixServer(path, Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.servers.append(server)
        return path, calls

    def run_client(self, candidates, operation="read"):
        run = subprocess.run([str(self.binary), operation, *candidates], check=True, capture_output=True, text=True, timeout=15)
        return json.loads(run.stdout)

    def test_prefers_current_service_over_legacy(self):
        modern, calls = self.server("modern.sock", {"tun": {"enable": True}})
        legacy, old_calls = self.server("legacy.sock", {"tun": {"enable": False}})
        result = self.run_client([modern, legacy])
        self.assertEqual(result["socket"], modern)
        self.assertTrue(result["first"]["tun"]["enable"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(old_calls, [])

    def test_falls_back_from_missing_or_stale_socket(self):
        legacy, _ = self.server("legacy.sock", {"tun": {"enable": True}})
        stale = str(self.root_case / "stale.sock")
        with socket.socket(socket.AF_UNIX) as sock:
            sock.bind(stale)
        for first in [str(self.root_case / "missing.sock"), stale]:
            self.assertEqual(self.run_client([first, legacy])["socket"], legacy)

    def test_rejects_regular_file_and_invalid_config(self):
        regular = self.root_case / "regular.sock"
        regular.write_text("not a socket")
        invalid, _ = self.server("invalid.sock", {"tun": {}})
        good, _ = self.server("good.sock", {"tun": {"enable": True}})
        self.assertEqual(self.run_client([str(regular), invalid, good])["socket"], good)

    def test_reports_disabled_separately_from_unknown(self):
        disabled, _ = self.server("disabled.sock", {"tun": {"enable": False}})
        self.assertFalse(self.run_client([disabled])["first"]["tun"]["enable"])
        unknown = self.run_client([str(self.root_case / "missing.sock")])
        self.assertEqual(unknown["first"], {})
        self.assertEqual(unknown["socket"], "")

    def test_cached_read_rediscovers_after_endpoint_fails(self):
        modern, _ = self.server("modern.sock", {"tun": {"enable": True}}, fail_after_first=True)
        legacy, _ = self.server("legacy.sock", {"tun": {"enable": False}})
        result = self.run_client([modern, legacy], "reconnect")
        self.assertEqual(result["socket"], legacy)
        self.assertFalse(result["second"]["tun"]["enable"])

    def test_body_is_passed_without_shell_interpolation(self):
        modern, calls = self.server("modern.sock", {"tun": {"enable": True}})
        self.run_client([modern], "write")
        self.assertEqual(calls[-1], ("PATCH", {"name": "a'b $()"}))

    def test_dropped_write_response_is_not_replayed(self):
        modern, calls = self.server("modern.sock", {"tun": {"enable": True}}, drop_write=True)
        legacy, old_calls = self.server("legacy.sock", {"tun": {"enable": True}})
        result = self.run_client([modern, legacy], "drop-write")
        self.assertEqual(result["write"], "")
        self.assertEqual(sum(method == "PATCH" for method, _ in calls), 1)
        self.assertEqual(old_calls, [])

    def test_large_payload_over_64kb_reads_completely(self):
        large_nodes = [f"SG-Node-{i:04d}-" + ("x" * 60) for i in range(1800)]
        modern, _ = self.server("large.sock", {"tun": {"enable": True}, "nodes": large_nodes})
        result = self.run_client([modern])
        self.assertEqual(len(result["first"]["nodes"]), 1800)
        self.assertEqual(result["first"]["nodes"][-1], large_nodes[-1])

    def test_hung_socket_times_out_distinct_from_missing(self):
        hung_path = str(self.root_case / "hung.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(hung_path)
        srv.listen(4)
        held = []

        def accept_and_hold():
            try:
                conn, _ = srv.accept()
                held.append(conn)
            except OSError:
                pass

        t = threading.Thread(target=accept_and_hold, daemon=True)
        t.start()
        try:
            hung = self.run_client([hung_path], "timeout-meta")
            self.assertIsNone(hung["body"])
            self.assertTrue(hung["timedOut"])
            self.assertLess(hung["elapsed"], 1.2)

            missing = self.run_client([str(self.root_case / "nope.sock")], "timeout-meta")
            self.assertIsNone(missing["body"])
            self.assertFalse(missing["timedOut"])
            self.assertLess(missing["elapsed"], 0.2)

            legacy, _ = self.server("legacy-fallback.sock", {"tun": {"enable": True}})
            failover = self.run_client([hung_path, legacy], "timeout-meta")
            self.assertIsNotNone(failover["body"])
            self.assertFalse(failover["timedOut"])
        finally:
            for c in held:
                c.close()
            srv.close()

    def test_no_subprocess_cli_regressions_in_source(self):
        source = (Path(__file__).resolve().parents[1] / "main.swift").read_text()
        forbidden = ["/usr/bin/curl", "/usr/bin/dscacheutil", "/sbin/route", "defaults read", "sed -i"]
        found = [token for token in forbidden if token in source]
        self.assertEqual(
            found, [],
            f"Do not shell out to external CLI tools ({found}); use in-process Darwin/Network/dnssd APIs to avoid swap-pressure timeouts."
        )

    def test_no_main_sync_deadlock_hazards_in_source(self):
        source = (Path(__file__).resolve().parents[1] / "main.swift").read_text()
        self.assertNotIn(
            "DispatchQueue.main.sync",
            source,
            "Background queues must never block on DispatchQueue.main.sync; use OSAllocatedUnfairLock so emergency cuts work even when AppKit main thread is stalled."
        )

    def test_chunked_transfer_encoding_reads_completely(self):
        chunked_path = str(self.root_case / "chunked.sock")
        payload = json.dumps({"tun": {"enable": True}, "items": [f"n-{i}" for i in range(120)]}).encode()
        mid = len(payload) // 2
        part1, part2 = payload[:mid], payload[mid:]
        wire = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            + f"{len(part1):x};ext=1\r\n".encode() + part1 + b"\r\n"
            + f"{len(part2):x}\r\n".encode() + part2 + b"\r\n"
            + b"0\r\n\r\n"
        )
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(chunked_path)
        srv.listen(4)

        def serve():
            try:
                conn, _ = srv.accept()
                with conn:
                    conn.recv(1024)
                    conn.sendall(wire)
            except OSError:
                pass

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            result = self.run_client([chunked_path])
            self.assertEqual(result["socket"], chunked_path)
            self.assertTrue(result["first"]["tun"]["enable"])
            self.assertEqual(len(result["first"]["items"]), 120)
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
