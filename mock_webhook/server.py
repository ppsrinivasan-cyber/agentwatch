"""Mock security webhook receiver (stands in for Slack / PagerDuty / a SOAR endpoint).

POST /hooks/security   receive an AgentWatch alert (Slack-compatible JSON)
GET  /hooks            JSON list of received deliveries
GET  /                 auto-refreshing HTML view of deliveries
"""
import html
import json
import logging
import os
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s webhook %(message)s")
log = logging.getLogger("mock-webhook")
DELIVERIES, LOCK = [], threading.Lock()
LOG_FILE = os.environ.get("WEBHOOK_LOG", "output/webhook_received.ndjson")


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != "/hooks/security":
            return self._send(404, {"error": "not found"})
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            p = json.loads(raw)
        except json.JSONDecodeError:
            return self._send(400, {"error": "invalid json"})
        a = p.get("alert") or {}
        rec = {"received_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "alert_id": a.get("alert_id"), "severity": a.get("severity"), "text": p.get("text"),
               "category": a.get("category"), "user": (a.get("context") or {}).get("user"),
               "action": a.get("recommended_action")}
        with LOCK:
            DELIVERIES.append(rec)
        try:
            os.makedirs(os.path.dirname(LOG_FILE) or ".", exist_ok=True)
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(rec) + "\n")
        except OSError:
            pass
        log.info("received %s %s", rec["alert_id"], rec["text"])
        self._send(200, {"ok": True, "received": rec["alert_id"]})

    def do_GET(self):
        if self.path == "/hooks":
            return self._send(200, {"count": len(DELIVERIES), "deliveries": DELIVERIES[::-1]})
        if self.path == "/healthz":
            return self._send(200, {"ok": True})
        rows = "".join(
            f"<tr><td>{html.escape(d['received_at'])}</td><td class='{html.escape(str(d['severity']))}'>"
            f"{html.escape(str(d['severity']))}</td><td>{html.escape(str(d['alert_id']))}</td>"
            f"<td>{html.escape(str(d['text']))}<div class=a>{html.escape(str(d['action']))}</div></td></tr>"
            for d in DELIVERIES[::-1])
        page = f"""<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=3>
<meta name=viewport content="width=device-width, initial-scale=1">
<title>Mock webhook receiver</title><style>
body{{font:14px/1.45 system-ui,sans-serif;margin:24px;color:#1d2731;background:#f3f5f7}}
table{{border-collapse:collapse;width:100%;background:#fff}}td,th{{padding:8px 10px;border-bottom:1px solid #dde3e9;text-align:left;vertical-align:top}}
.critical{{color:#b0124f;font-weight:700}}.high{{color:#c2410c;font-weight:700}}.a{{color:#5b6b7c;font-size:12px;margin-top:4px}}
@media (prefers-color-scheme:dark){{body{{background:#161c23;color:#dbe3ea}}table{{background:#1e2731}}td,th{{border-color:#2d3945}}.a{{color:#8b9aa9}}}}
</style><h1 style="font-size:20px">Mock security webhook: {len(DELIVERIES)} deliveries</h1>
<p>Stands in for Slack, PagerDuty or a SOAR. AgentWatch posts every high and critical alert here. This page refreshes every 3 seconds.</p>
<table><tr><th>Received</th><th>Severity</th><th>Alert</th><th>Message</th></tr>{rows or '<tr><td colspan=4>Waiting for alerts…</td></tr>'}</table>"""
        self._send(200, page, "text/html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "9000"))
    log.info("listening on :%d  POST /hooks/security", port)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
