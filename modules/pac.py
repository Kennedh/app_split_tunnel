"""Generate and serve a PAC allowlist for application-level split proxying."""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterable


def _js_array(values: Iterable[str]) -> str:
    return json.dumps(list(values), ensure_ascii=True)


def build_pac(
    proxy_host: str,
    proxy_port: int,
    proxy_exact_hosts: Iterable[str],
    proxy_patterns: Iterable[str],
    direct_exact_hosts: Iterable[str],
    direct_patterns: Iterable[str],
    proxy_window_seconds: int = 0,
) -> str:
    until_ms = 0
    if proxy_window_seconds > 0:
        until_ms = int((time.time() + proxy_window_seconds) * 1000)

    return f'''// Generated selective split-routing PAC.
var PROXY = "SOCKS5 {proxy_host}:{proxy_port}";
var PROXY_UNTIL_MS = {until_ms};
var PROXY_EXACT = {_js_array(proxy_exact_hosts)};
var PROXY_PATTERNS = {_js_array(proxy_patterns)};
var DIRECT_EXACT = {_js_array(direct_exact_hosts)};
var DIRECT_PATTERNS = {_js_array(direct_patterns)};

function inList(host, items) {{
  for (var i = 0; i < items.length; i++) {{
    if (host === items[i]) return true;
  }}
  return false;
}}

function matches(host, patterns) {{
  for (var i = 0; i < patterns.length; i++) {{
    if (shExpMatch(host, patterns[i])) return true;
  }}
  return false;
}}

function FindProxyForURL(url, host) {{
  host = host.toLowerCase();
  if (isPlainHostName(host) || host === "localhost" || host === "127.0.0.1") return "DIRECT";
  if (inList(host, DIRECT_EXACT) || matches(host, DIRECT_PATTERNS)) return "DIRECT";
  if (PROXY_UNTIL_MS > 0 && Date.now() >= PROXY_UNTIL_MS) return "DIRECT";
  if (inList(host, PROXY_EXACT) || matches(host, PROXY_PATTERNS)) return PROXY;
  return "DIRECT";
}}
'''


class PacServer:
    """Tiny loopback-only PAC server.

    HTTP is used instead of a file:// PAC URL because Chromium/Electron builds
    are more consistent about loading PAC files over HTTP. The listener is
    bound to 127.0.0.1 and serves exactly one generated script.
    """

    def __init__(self, pac_text: str, host: str = "127.0.0.1"):
        self.pac_text = pac_text.encode("utf-8")
        self.host = host
        self.httpd: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> str:
        body = self.pac_text

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.split("?", 1)[0] != "/proxy.pac":
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                return

        self.httpd = ThreadingHTTPServer((self.host, 0), Handler)
        port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="pac-server", daemon=True)
        self.thread.start()
        return f"http://{self.host}:{port}/proxy.pac"

    def stop(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
        self.thread = None
