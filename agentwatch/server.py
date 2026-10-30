"""AgentWatch HTTP server (stdlib only).

GET  /                         dashboard UI
GET  /api/stats                counts by category / severity / status, contained sessions, flagged files
GET  /api/alerts               filterable feed: severity, min_severity, category, status, agent, user, repo,
                               rule, session, q, limit
GET  /api/alerts/<id>          single alert
POST /api/alerts/<id>/status   {"status": "acknowledged"|"resolved"|"open"|"false_positive", "note": "..."}
POST /api/events               ingest one JSON event, a JSON array, or NDJSON. Returns per-event decision
                               (allow | require_approval | block) so an agent gateway can enforce inline.
POST /api/replay               reset state and replay the bundled sample dataset
GET  /api/events?limit=        recent events (metadata only)
GET  /api/responses            automated response action log
GET  /api/rules                detection rules + MITRE mappings
POST /api/mock-webhook         built-in webhook receiver (used when WEBHOOK_URL is not set)
GET  /api/mock-webhook         deliveries received by the built-in receiver
GET  /healthz

Env: PORT (8080), HOST (0.0.0.0), INGEST_FILE, STREAM_DELAY (seconds between replayed events),
     WEBHOOK_URL, OUTPUT_DIR (output), POLICY_FILE
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .detectors import RULES
from .engine import Engine, load_policy
from .responses import now_iso

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("agentwatch")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
PORT = int(os.environ.get("PORT", "8080"))
HOST = os.environ.get("HOST", "0.0.0.0")
INGEST_FILE = os.environ.get("INGEST_FILE", os.path.join(ROOT, "data", "sample_agent_activity.ndjson"))
STREAM_DELAY = float(os.environ.get("STREAM_DELAY", "0.25"))
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", os.path.join(ROOT, "output"))
WEBHOOK_URL = os.environ.get("WEBHOOK_URL") or f"http://127.0.0.1:{PORT}/api/mock-webhook"
MAX_BODY = 10 * 1024 * 1024


class State:
    def __init__(self):
        self.policy = load_policy()
        self.engine = Engine(self.policy, OUTPUT_DIR, WEBHOOK_URL)
        self.mock_deliveries: list[dict] = []
        self.replay_status = {"running": False, "file": None, "sent": 0, "total": 0}
        self.generation = 0
        self.lock = threading.Lock()

    def reset(self):
        with self.lock:
            self.generation += 1
            self.engine = Engine(self.policy, OUTPUT_DIR, WEBHOOK_URL)
            self.mock_deliveries = []

    def replay(self, path: str, delay: float):
        gen = self.generation
        try:
            with open(path, encoding="utf-8") as f:
                lines = [l for l in f if l.strip()]
        except OSError as ex:
            log.error("cannot read %s: %s", path, ex)
            return
        self.replay_status = {"running": True, "file": os.path.basename(path), "sent": 0, "total": len(lines)}
        log.info("replaying %d events from %s (delay %.2fs)", len(lines), path, delay)
        for line in lines:
            if gen != self.generation:
                return  # a newer replay started
            self.engine.ingest_lines([line])
            self.replay_status["sent"] += 1
            if delay:
                time.sleep(delay)
        self.replay_status["running"] = False
        log.info("replay finished: %d alerts", len(self.engine.alerts))


STATE: State | None = None


def start_replay(path=INGEST_FILE, delay=STREAM_DELAY):
    threading.Thread(target=STATE.replay, args=(path, delay), daemon=True).start()


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentWatch/1.0"

    def log_message(self, fmt, *args):
        if not self.path.startswith(("/api/stats", "/api/alerts", "/api/responses", "/healthz", "/api/events?")):
            log.info("%s %s", self.address_string(), fmt % args)

    # ------------------------------------------------------------------ helpers
    def _send(self, code: int, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else (
            json.dumps(body, ensure_ascii=False, default=str).encode() if ctype == "application/json" else body.encode())
        self.send_response(code)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError("body too large")
        return self.rfile.read(n) if n else b""

    def _qs(self):
        q = parse_qs(urlparse(self.path).query)
        return {k: v[0] for k, v in q.items() if v and v[0] != ""}

    # ------------------------------------------------------------------ GET
    def do_GET(self):
        path = urlparse(self.path).path
        eng = STATE.engine
        if path in ("/", "/index.html"):
            with open(os.path.join(STATIC, "index.html"), "rb") as f:
                return self._send(200, f.read(), "text/html")
        if path == "/healthz":
            return self._send(200, {"ok": True, "time": now_iso()})
        if path == "/api/stats":
            return self._send(200, {**eng.stats(), "replay": STATE.replay_status, "webhook_url": WEBHOOK_URL})
        if path == "/api/alerts":
            q = self._qs()
            limit = int(q.pop("limit", 500))
            allowed = {"severity", "min_severity", "category", "status", "agent", "user", "repo", "rule", "session", "q"}
            alerts = eng.query(limit=limit, **{k: v for k, v in q.items() if k in allowed})
            return self._send(200, {"count": len(alerts), "alerts": alerts})
        m = re.fullmatch(r"/api/alerts/(AW-\d+)", path)
        if m:
            a = eng.alert_index.get(m.group(1))
            return self._send(200, a) if a else self._send(404, {"error": "alert not found"})
        if path == "/api/events":
            limit = int(self._qs().get("limit", 100))
            return self._send(200, {"events": list(reversed(eng.events[-limit:]))})
        if path == "/api/responses":
            acts = eng.responder.actions if eng.responder else []
            return self._send(200, {"actions": list(reversed(acts[-300:]))})
        if path == "/api/rules":
            return self._send(200, {"rules": list(RULES.values())})
        if path == "/api/mock-webhook":
            return self._send(200, {"deliveries": STATE.mock_deliveries[-100:]})
        return self._send(404, {"error": "not found"})

    # ------------------------------------------------------------------ POST
    def do_POST(self):
        path = urlparse(self.path).path
        try:
            raw = self._body()
        except ValueError as ex:
            return self._send(413, {"error": str(ex)})
        if path == "/api/events":
            text = raw.decode("utf-8", "replace").strip()
            if not text:
                return self._send(400, {"error": "empty body"})
            try:
                parsed = json.loads(text)
                lines = parsed if isinstance(parsed, list) else [parsed]
            except json.JSONDecodeError:
                lines = text.splitlines()  # NDJSON
            results = STATE.engine.ingest_lines(lines)
            return self._send(200, {"processed": len(results), "results": results})
        m = re.fullmatch(r"/api/alerts/(AW-\d+)/status", path)
        if m:
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return self._send(400, {"error": "invalid JSON"})
            status = body.get("status")
            if status not in ("open", "acknowledged", "resolved", "false_positive"):
                return self._send(400, {"error": "status must be open|acknowledged|resolved|false_positive"})
            a = STATE.engine.set_status(m.group(1), status, body.get("note", ""))
            return self._send(200, a) if a else self._send(404, {"error": "alert not found"})
        if path == "/api/replay":
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                body = {}
            STATE.reset()
            start_replay(INGEST_FILE, float(body.get("delay", STREAM_DELAY)))
            return self._send(202, {"replaying": os.path.basename(INGEST_FILE)})
        if path == "/api/mock-webhook":
            try:
                payload = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                payload = {"raw": raw.decode("utf-8", "replace")}
            STATE.mock_deliveries.append({"received_at": now_iso(), "text": payload.get("text"),
                                          "alert_id": (payload.get("alert") or {}).get("alert_id")})
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "not found"})


def main():
    global STATE
    STATE = State()
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    log.info("AgentWatch dashboard on http://localhost:%d  (webhook -> %s)", PORT, WEBHOOK_URL)
    if INGEST_FILE and os.path.exists(INGEST_FILE) and os.environ.get("AUTO_REPLAY", "true").lower() != "false":
        start_replay()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
