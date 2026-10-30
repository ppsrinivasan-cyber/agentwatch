"""Automated response actions.

Four actions run automatically based on ``response_policy`` thresholds in config/policy.json:

* quarantine_log   – append alert + raw event to output/quarantine.ndjson (evidence locker)
* flag_file        – register the file in output/flagged_files.json and drop a marker in output/flags/
* webhook          – POST a Slack-compatible JSON payload to WEBHOOK_URL (async, with retries)
* suspend_session  – add the agent session to output/blocked_sessions.json; the engine then returns
                     ``decision: block`` for every later event from that session (inline enforcement)

Every action is appended to output/response_actions.ndjson and attached to the alert.
"""
from __future__ import annotations

import json
import os
import queue
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from .utils import SEVERITY_ORDER, redact_text


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Responder:
    def __init__(self, output_dir: str, policy: dict, webhook_url: str | None = None, lock=None):
        self.out = output_dir
        self.policy = policy.get("response_policy", {})
        self.webhook_url = webhook_url
        self.lock = lock or threading.RLock()
        self.blocked_sessions: dict[str, dict] = {}
        self.flagged_files: dict[str, dict] = {}
        self.actions: list[dict] = []
        os.makedirs(os.path.join(self.out, "flags"), exist_ok=True)
        self._q: queue.Queue = queue.Queue()
        self._worker = threading.Thread(target=self._webhook_worker, daemon=True)
        self._worker.start()

    # ------------------------------------------------------------------ helpers
    def _gte(self, sev: str, key: str, default: str) -> bool:
        return SEVERITY_ORDER[sev] >= SEVERITY_ORDER[self.policy.get(key, default)]

    def _append(self, name: str, obj: dict):
        with open(os.path.join(self.out, name), "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    def _record(self, alert: dict, action: str, status: str, detail: str) -> dict:
        rec = {"at": now_iso(), "action": action, "status": status, "detail": detail,
               "alert_id": alert["alert_id"], "severity": alert["severity"], "title": alert["title"]}
        with self.lock:
            alert["response_actions"].append(rec)
            self.actions.append(rec)
        self._append("response_actions.ndjson", rec)
        return rec

    # ------------------------------------------------------------------ main entry
    def respond(self, alert: dict, event: dict):
        sev = alert["severity"]
        if self._gte(sev, "quarantine_min_severity", "high"):
            self.quarantine(alert, event)
        if alert["context"].get("file_path") and self._gte(sev, "flag_file_min_severity", "medium"):
            self.flag_file(alert)
        if self._gte(sev, "webhook_min_severity", "high"):
            self.webhook(alert)
        if self._gte(sev, "suspend_session_min_severity", "critical"):
            self.suspend_session(alert)

    # ------------------------------------------------------------------ actions
    def quarantine(self, alert, event):
        safe_event = json.loads(redact_text(json.dumps(event, ensure_ascii=False)))
        self._append("quarantine.ndjson", {"quarantined_at": now_iso(), "alert": {
            k: alert[k] for k in ("alert_id", "rule_id", "title", "severity", "category", "mitre", "evidence",
                                  "recommended_action", "context")}, "event": safe_event})
        self._record(alert, "quarantine_log", "done", "Alert and raw event written to output/quarantine.ndjson")

    def flag_file(self, alert):
        ctx = alert["context"]
        key = f"{ctx.get('repo', '?')}:{ctx['file_path']}"
        with self.lock:
            entry = self.flagged_files.setdefault(key, {
                "repo": ctx.get("repo"), "path": ctx["file_path"], "first_flagged": now_iso(), "alerts": []})
            entry["alerts"].append({"alert_id": alert["alert_id"], "severity": alert["severity"],
                                    "title": alert["title"]})
            entry["last_flagged"] = now_iso()
            snapshot = dict(self.flagged_files)
        with open(os.path.join(self.out, "flagged_files.json"), "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
        marker = re.sub(r"[^A-Za-z0-9._-]+", "__", key) + ".flag"
        with open(os.path.join(self.out, "flags", marker), "w", encoding="utf-8") as f:
            f.write(f"FLAGGED by AgentWatch {now_iso()}\nalert={alert['alert_id']} severity={alert['severity']}\n"
                    f"{alert['title']}\nDo not merge or execute until reviewed.\n")
        self._record(alert, "flag_file", "done", f"Flagged {key} (output/flags/{marker})")

    def suspend_session(self, alert):
        sid = alert["context"].get("session_id")
        if not sid:
            return
        with self.lock:
            if sid in self.blocked_sessions:
                return
            self.blocked_sessions[sid] = {"session_id": sid, "user": alert["context"].get("user"),
                                          "agent": alert["context"].get("agent"), "blocked_at": now_iso(),
                                          "reason": f"{alert['alert_id']}: {alert['title']}"}
            snapshot = dict(self.blocked_sessions)
        with open(os.path.join(self.out, "blocked_sessions.json"), "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
        self._record(alert, "suspend_session", "done",
                     f"Session {sid} suspended; later events from it receive decision=block")

    def webhook(self, alert):
        if not self.webhook_url:
            self._record(alert, "webhook", "skipped", "WEBHOOK_URL not configured")
            return
        rec = self._record(alert, "webhook", "queued", f"POST {self.webhook_url}")
        self._q.put((alert, rec))

    def _payload(self, alert):
        icon = {"critical": ":rotating_light:", "high": ":warning:"}.get(alert["severity"], ":mag:")
        techs = ", ".join(t["technique_id"] for t in alert["mitre"])
        c = alert["context"]
        return {
            "text": f"{icon} [{alert['severity'].upper()}] {alert['title']}",
            "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text":
                        f"*{alert['category']}* · `{alert['rule_id']}` · {techs}\n"
                        f"user `{c.get('user')}` · agent `{c.get('agent')}` · repo `{c.get('repo')}`\n"
                        f"*Action:* {alert['recommended_action']}"}}],
            "alert": alert,
        }

    def _webhook_worker(self):
        while True:
            alert, rec = self._q.get()
            body = json.dumps(self._payload(alert), default=str).encode()
            status, detail = "failed", ""
            for attempt in range(3):
                try:
                    req = urllib.request.Request(self.webhook_url, data=body, method="POST",
                                                 headers={"Content-Type": "application/json",
                                                          "X-AgentWatch-Alert": alert["alert_id"]})
                    with urllib.request.urlopen(req, timeout=3) as r:
                        status, detail = "delivered", f"HTTP {r.status} from {self.webhook_url}"
                        break
                except (urllib.error.URLError, OSError) as ex:
                    detail = f"attempt {attempt + 1}: {ex}"
                    time.sleep(0.4 * (attempt + 1))
            with self.lock:
                rec["status"], rec["detail"], rec["completed_at"] = status, detail, now_iso()
            self._append("response_actions.ndjson", {**rec, "update": True})
            self._q.task_done()

    def flush(self, timeout: float = 15):
        end = time.time() + timeout
        while self._q.unfinished_tasks and time.time() < end:
            time.sleep(0.05)
