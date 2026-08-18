"""
Bundled Practice Target: a small, deliberately misconfigured local web
server (plus a couple of decoy TCP banner listeners) so Rupux's own
scanners always have something safe and legal to point at.

SAFETY DESIGN:
  - Binds ONLY to 127.0.0.1 (localhost) -- never 0.0.0.0. It is
    physically unreachable from any other machine on the network,
    regardless of firewall settings.
  - Must be started explicitly by the user; never runs automatically.
  - Contains configuration-level weaknesses only (missing security
    headers, an exposed fake secrets file, an unauthenticated "admin"
    route, an insecure cookie, permissive CORS) -- the same categories
    Rupux's own Web-App Vulnerability Scanner, Port Scanner, and IDS
    System already detect. It deliberately does NOT include real
    injection surfaces (SQLi/XSS with a live backend) -- those need a
    different, more heavily sandboxed tool (e.g. DVWA/Juice Shop) and
    are out of scope here.
  - All "secrets" served are obvious placeholders, clearly labeled as
    fake in their own content.

Built on Python's standard library only (http.server, socketserver) --
no extra dependency just for a practice fixture.
"""
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

DEFAULT_HTTP_PORT = 8899
DECOY_PORTS = {
    2121: b"220 PracticeFTP (demo, not a real FTP server) ready.\r\n",
    2323: b"PracticeTelnet demo banner -- for Rupux port-scan practice only.\r\n",
}

FAKE_ENV_CONTENT = (
    "# This is a DELIBERATELY exposed practice file. Nothing here is real.\n"
    "DB_PASSWORD=practice_only_not_real_123\n"
    "API_KEY=demo-fake-key-0000000000\n"
)

FAKE_GIT_CONFIG = (
    "[core]\n"
    "\trepositoryformatversion = 0\n"
    "# Deliberately exposed for practice — not a real repository.\n"
)

HOME_PAGE_HTML = """<!DOCTYPE html>
<html><head><title>Rupux Practice Target</title></head>
<body style="font-family: sans-serif; max-width: 640px; margin: 40px auto;">
<h1>Rupux Practice Target</h1>
<p>This local-only server has several <b>deliberate</b> misconfigurations for you
to find with Rupux's own tools. Nothing here is a real system or real data.</p>
<ul>
<li><a href="/secret-admin/">/secret-admin/</a> — an "admin panel" with no login check</li>
<li><a href="/.env">/.env</a> — an exposed fake secrets file</li>
<li><a href="/.git/config">/.git/config</a> — an exposed fake git config</li>
<li><a href="/files/">/files/</a> — a directory listing</li>
<li><a href="/api/data">/api/data</a> — an API with permissive CORS</li>
<li><a href="/login">/login</a> — sets a cookie missing security flags</li>
</ul>
<p>Try pointing Web-App Vulnerability Scan at this server's address, and
Port Scanner at 127.0.0.1 to find the decoy services too.</p>
</body></html>"""

ADMIN_PAGE_HTML = """<!DOCTYPE html>
<html><head><title>Admin Panel</title></head>
<body style="font-family: sans-serif;">
<h1>Admin Panel</h1>
<p><b>You reached this page with no login required.</b> In a real application,
this represents a broken access control vulnerability — sensitive functionality
exposed without authentication.</p>
</body></html>"""

FILES_LISTING_HTML = """<!DOCTYPE html>
<html><head><title>Index of /files/</title></head>
<body style="font-family: monospace;">
<h1>Index of /files/</h1>
<ul>
<li><a href="/files/backup.zip">backup.zip</a> (demo placeholder, not a real file)</li>
<li><a href="/files/notes.txt">notes.txt</a> (demo placeholder, not a real file)</li>
</ul>
</body></html>"""


class _PracticeTargetHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.2.3"  # deliberately old-looking, for the info-disclosure lesson
    sys_version = ""                 # suppress the real Python version in the banner

    def log_message(self, format, *args):
        pass  # keep the console quiet; Rupux's own logger isn't wired here on purpose

    def _send(self, status: int, content_type: str, body: bytes, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # Deliberately NOT setting: CSP, X-Frame-Options, X-Content-Type-Options,
        # Strict-Transport-Security, Referrer-Policy, Permissions-Policy.
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/":
            self._send(200, "text/html", HOME_PAGE_HTML.encode())
        elif path == "/robots.txt":
            self._send(200, "text/plain", b"User-agent: *\nDisallow: /secret-admin/\nDisallow: /files/backup.zip\n")
        elif path == "/secret-admin/" or path == "/secret-admin":
            self._send(200, "text/html", ADMIN_PAGE_HTML.encode())
        elif path == "/.env":
            self._send(200, "text/plain", FAKE_ENV_CONTENT.encode())
        elif path == "/.git/config":
            self._send(200, "text/plain", FAKE_GIT_CONFIG.encode())
        elif path == "/files/":
            self._send(200, "text/html", FILES_LISTING_HTML.encode())
        elif path == "/files/backup.zip":
            self._send(200, "application/octet-stream", b"PRACTICE_PLACEHOLDER_NOT_A_REAL_ARCHIVE")
        elif path == "/files/notes.txt":
            self._send(200, "text/plain", b"These are placeholder notes for practice only.")
        elif path == "/api/data":
            self._send(200, "application/json", b'{"demo": true, "message": "practice API response"}',
                       extra_headers={"Access-Control-Allow-Origin": "*"})
        elif path == "/login":
            self._send(200, "text/html", b"<html><body>Logged in (demo).</body></html>",
                       extra_headers={"Set-Cookie": "session_id=demo123abc; Path=/"})  # no Secure/HttpOnly/SameSite
        else:
            self._send(404, "text/plain", b"Not Found")

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()


class _DecoyPortListener(threading.Thread):
    """A trivial TCP listener that sends a fixed banner to whoever connects,
    then closes -- gives Port Scanner something realistic to find and grab
    a banner from, without implementing any real protocol."""

    def __init__(self, port: int, banner: bytes):
        super().__init__(daemon=True)
        self.port = port
        self.banner = banner
        self._stop_event = threading.Event()
        self._sock: Optional[socket.socket] = None

    def run(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen(5)
        self._sock.settimeout(0.5)
        while not self._stop_event.is_set():
            try:
                conn, _ = self._sock.accept()
                try:
                    conn.sendall(self.banner)
                except Exception:
                    pass
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        self._stop_event.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass


class PracticeTarget:
    """Controller: start()/stop() the local practice web server and decoy ports."""

    def __init__(self, http_port: int = DEFAULT_HTTP_PORT):
        self.http_port = http_port
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._http_thread: Optional[threading.Thread] = None
        self._decoy_listeners = []
        self.running = False

    def start(self) -> str:
        """Starts the server. Returns the base URL, or raises if the port is busy."""
        self._httpd = ThreadingHTTPServer(("127.0.0.1", self.http_port), _PracticeTargetHandler)
        self._http_thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._http_thread.start()

        for port, banner in DECOY_PORTS.items():
            listener = _DecoyPortListener(port, banner)
            listener.start()
            self._decoy_listeners.append(listener)

        self.running = True
        return f"http://127.0.0.1:{self.http_port}/"

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        for listener in self._decoy_listeners:
            listener.stop()
        self._decoy_listeners = []
        self.running = False
