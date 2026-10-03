"""Local HTTP/JSON front end.

Binds to 127.0.0.1 only. Every call needs the shared token from config.json,
which is what stops another process on the machine from driving your game.
"""

import json
import os
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .bridge import TOOLS, Bridge
from .events import HEARTBEAT_SECONDS, KEEPALIVE, frame

# A client that vanished leaves the socket open until the next write fails, so
# cap how long one write may park. Without this a browser tab that closed
# mid-session would hold a handler thread until the bridge stopped.
WRITE_TIMEOUT = 20.0
# How long the stream waits for an event before checking the socket. One second
# is frequent enough that a disconnect is noticed quickly and rare enough to
# cost nothing.
POLL_SECONDS = 1.0


def ensure_token(config):
    token = config.get("token")
    if not token:
        token = secrets.token_hex(16)
        config.data["token"] = token
        config.save()
    return token


class Handler(BaseHTTPRequestHandler):
    server_version = "CEBridge/1.0"
    bridge = None
    token = None

    def log_message(self, fmt, *args):
        if self.server.verbose:
            self.server.bridge.log.debug("http %s", fmt % args)

    def _send(self, code, payload):
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorised(self):
        supplied = self.headers.get("X-CE-Bridge-Token", "")
        if not supplied:
            query = parse_qs(urlparse(self.path).query)
            supplied = (query.get("token") or [""])[0]
        return secrets.compare_digest(supplied, self.token)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/events":
            return self._stream_events()
        if path in ("/health", "/api/ping"):
            if not self._authorised():
                return self._send(401, {"ok": False, "error": "bad or missing token"})
            return self._send(200, {"ok": True, "result": self.bridge.ping()})
        if path == "/api/tools":
            if not self._authorised():
                return self._send(401, {"ok": False, "error": "bad or missing token"})
            return self._send(200, {"ok": True, "result": {"tools": list(TOOLS)}})
        if path == "/api/status":
            if not self._authorised():
                return self._send(401, {"ok": False, "error": "bad or missing token"})
            return self._send(200, {"ok": True, "result": self.bridge.status()})
        return self._send(404, {"ok": False, "error": f"no route for {path}"})

    def _stream_events(self):
        """Hold the connection open and write every state change to it.

        The token may arrive in the query string as well as the header, because
        EventSource cannot set headers and some clients only speak that.
        """
        if not self._authorised():
            return self._send(401, {"ok": False, "error": "bad or missing token"})

        bus = self.bridge.events
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        # No Content-Length: the body ends when the stream ends. Saying so
        # explicitly keeps clients from waiting for a length that never comes.
        self.send_header("Connection", "close")
        self.end_headers()

        try:
            self.connection.settimeout(WRITE_TIMEOUT)
        except OSError:
            return

        subscription = bus.subscribe()
        # The client gets the current state immediately, so it can render
        # without a second round trip and without waiting for something to
        # change. That is the whole point of a live indicator.
        try:
            self._write(frame("hello", self.bridge.status(), bus.peek_sequence()))
            last_write = time.time()
            while not subscription.closed:
                event = subscription.get(timeout=POLL_SECONDS)
                if event is not None:
                    self._write(frame(event["kind"], event["data"], event["seq"]))
                    last_write = time.time()
                elif time.time() - last_write >= HEARTBEAT_SECONDS:
                    self._write(KEEPALIVE)
                    last_write = time.time()
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass
        except Exception as error:
            self.bridge.log.debug("event stream ended: %s", error)
        finally:
            subscription.close()
            try:
                self.connection.close()
            except OSError:
                pass

    def _write(self, payload):
        self.wfile.write(payload)
        self.wfile.flush()

    def do_POST(self):
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/"):
            return self._send(404, {"ok": False, "error": f"no route for {parsed.path}"})
        if not self._authorised():
            return self._send(401, {"ok": False, "error": "bad or missing token"})

        tool = parsed.path[len("/api/"):]
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            params = json.loads(raw.decode("utf-8") or "{}")
        except Exception as error:
            return self._send(400, {"ok": False, "error": f"invalid JSON body: {error}"})
        if not isinstance(params, dict):
            return self._send(400, {"ok": False, "error": "body must be a JSON object"})

        result = self.bridge.execute(tool, params)
        self.bridge.log.info("%s -> %s (%.0f ms)", tool,
                             "ok" if result.get("ok") else "error", result.get("elapsed_ms", 0))
        return self._send(200, result)


class BridgeServer:
    def __init__(self, bridge, verbose=False):
        self.bridge = bridge
        self.config = bridge.config
        self.token = ensure_token(self.config)
        handler = type("BoundHandler", (Handler,), {"bridge": bridge, "token": self.token})
        host = self.config.get("host", "127.0.0.1")
        port = int(self.config.get("port", 9877))
        self.httpd = ThreadingHTTPServer((host, port), handler)
        self.httpd.verbose = verbose
        self.httpd.daemon_threads = True
        self.httpd.bridge = bridge
        self.host, self.port = self.httpd.server_address
        self.publish_endpoint()

    def publish_endpoint(self):
        """Write the url and token where the opencode tools can find them.

        Putting this in the spool directory means the tools need no path or
        token configuration at all: they read one file from the temp directory
        that the bridge has already created for the Cheat Engine agent.
        """
        try:
            bridge_ce = self.bridge.ce
            bridge_ce.ensure_dir()
            path = os.path.join(bridge_ce.dir, "endpoint.json")
            payload = {
                "url": f"http://{self.host}:{self.port}",
                "host": self.host,
                "port": self.port,
                "token": self.token,
                "pid": os.getpid(),
                "published": time.time(),
            }
            temp = path + ".tmp"
            with open(temp, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
            os.replace(temp, path)
            return path
        except Exception as error:
            self.bridge.log.warn("could not publish the endpoint file: %s", error)
            return None

    def serve_forever(self):
        self.httpd.serve_forever()

    def start_background(self):
        thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        thread.start()
        return thread

    def shutdown(self):
        try:
            self.httpd.shutdown()
        except Exception:
            pass
        try:
            self.httpd.server_close()
        except Exception:
            pass
