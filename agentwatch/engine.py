"""Detection engine: validates events, runs rules, de-duplicates, correlates per session,
creates structured alerts, triggers responses and keeps in-memory state for the API."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from collections import Counter

from .detectors import DETECTORS, RULES, correlate
from .responses import Responder, now_iso
from .utils import SEVERITY_ORDER

log = logging.getLogger("agentwatch")

EVENT_TYPES = {"prompt", "completion", "file_read", "file_edit", "shell_command", "git_operation",
               "api_call", "package_install", "tool_call"}
REQUIRED = ("event_id", "timestamp", "event_type", "payload")


def load_policy(path: str | None = None) -> dict:
    path = path or os.environ.get("POLICY_FILE") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "policy.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def validate(event) -> str | None:
    if not isinstance(event, dict):
        return "event is not a JSON object"
    missing = [k for k in REQUIRED if k not in event]
    if missing:
        return f"missing fields: {', '.join(missing)}"
    if event["event_type"] not in EVENT_TYPES:
        return f"unknown event_type '{event['event_type']}'"
    if not isinstance(event["payload"], dict):
        return "payload must be an object"
    return None


class Engine:
    def __init__(self, policy: dict | None = None, output_dir: str = "output", webhook_url: str | None = None,
                 respond: bool = True, reset: bool = True):
        self.policy = policy or load_policy()
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        if reset:
            for name in ("alerts.ndjson", "quarantine.ndjson", "response_actions.ndjson", "flagged_files.json",
                         "blocked_sessions.json", "ingest_errors.ndjson"):
                p = os.path.join(output_dir, name)
                if os.path.exists(p):
                    os.remove(p)
            flags = os.path.join(output_dir, "flags")
            if os.path.isdir(flags):
                for f in os.listdir(flags):
                    os.remove(os.path.join(flags, f))
        self.lock = threading.RLock()
        self.responder = Responder(output_dir, self.policy, webhook_url, self.lock) if respond else None
        self.alerts: list[dict] = []
        self.alert_index: dict[str, dict] = {}
        self.dedupe: dict[str, dict] = {}
        self.sessions: dict[str, dict] = {}
        self.events: list[dict] = []
        self.event_types = Counter()
        self.errors: list[dict] = []
        self.started_at = now_iso()
        self._seq = 0

    # ------------------------------------------------------------------ ingestion
    def ingest_lines(self, lines) -> list[dict]:
        results = []
        for n, line in enumerate(lines, 1):
            line = line.strip() if isinstance(line, str) else line
            if not line:
                continue
            try:
                ev = json.loads(line) if isinstance(line, str) else line
            except json.JSONDecodeError as ex:
                self._error({"line": n}, f"invalid JSON: {ex}")
                continue
            results.append(self.process(ev))
        return results

    def _error(self, ev, msg):
        rec = {"at": now_iso(), "error": msg, "event_id": ev.get("event_id") if isinstance(ev, dict) else None}
        with self.lock:
            self.errors.append(rec)
        with open(os.path.join(self.output_dir, "ingest_errors.ndjson"), "a") as f:
            f.write(json.dumps(rec) + "\n")
        return {"event_id": rec["event_id"], "accepted": False, "error": msg, "alerts": [], "decision": "allow"}

    def process(self, event: dict) -> dict:
        err = validate(event)
        if err:
            return self._error(event, err)
        sid = event.get("session_id") or "unknown"
        with self.lock:
            blocked = self.responder and sid in self.responder.blocked_sessions
            self.event_types[event["event_type"]] += 1
            self.events.append({k: event.get(k) for k in ("event_id", "timestamp", "event_type", "session_id",
                                                          "user", "repo")} | {"agent": (event.get("agent") or {}).get("name")})
            if len(self.events) > 5000:
                self.events = self.events[-5000:]
        ctx = {"policy": self.policy}
        findings = []
        for rule_id, fn in DETECTORS:
            try:
                findings.extend(fn(event, ctx))
            except Exception as ex:  # a broken rule must never stop the pipeline
                log.exception("rule %s failed on %s", rule_id, event.get("event_id"))
                self._error(event, f"rule {rule_id} crashed: {ex}")
        new_alerts = []
        with self.lock:
            for f in findings:
                a = self._to_alert(f, event)
                if a:
                    new_alerts.append(a)
            state = self.sessions.setdefault(sid, {})
            for cf in correlate(state, new_alerts):
                a = self._to_alert(cf, event)
                if a:
                    new_alerts.append(a)
        if self.responder:
            for a in new_alerts:
                self.responder.respond(a, event)
        for a in new_alerts:
            with open(os.path.join(self.output_dir, "alerts.ndjson"), "a", encoding="utf-8") as fh:
                fh.write(json.dumps(a, ensure_ascii=False, default=str) + "\n")
        decision = "allow"
        top = max((SEVERITY_ORDER[a["severity"]] for a in new_alerts), default=0)
        if blocked or (self.responder and sid in self.responder.blocked_sessions):
            decision = "block"
        elif top >= SEVERITY_ORDER["high"]:
            decision = "require_approval"
        return {"event_id": event["event_id"], "accepted": True, "decision": decision,
                "session_blocked": bool(blocked), "alerts": [a["alert_id"] for a in new_alerts]}

    def _to_alert(self, f: dict, event: dict) -> dict | None:
        sid = event.get("session_id")
        key = hashlib.sha1(f"{f['rule_id']}|{sid}|{f['title']}|{f['evidence']['snippet']}".encode()).hexdigest()
        if key in self.dedupe:
            a = self.dedupe[key]
            a["occurrences"] += 1
            a["last_seen"] = event.get("timestamp")
            return None
        self._seq += 1
        agent = event.get("agent") or {}
        alert = {
            "alert_id": f"AW-{self._seq:05d}",
            "created_at": now_iso(),
            "event_time": event.get("timestamp"),
            "rule_id": f["rule_id"], "rule_name": f["rule_name"], "title": f["title"],
            "category": f["category"], "severity": f["severity"], "confidence": f["confidence"],
            "mitre": f["mitre"],
            "evidence": {"event_id": event.get("event_id"), "event_type": event.get("event_type"), **f["evidence"]},
            "recommended_action": f["recommended_action"],
            "context": {"user": event.get("user"), "agent": agent.get("name"), "agent_version": agent.get("version"),
                        "model": agent.get("model"), "session_id": sid, "repo": event.get("repo"),
                        "host": event.get("host"), "file_path": f.get("file_path")},
            "details": f.get("extra") or {},
            "status": "open", "occurrences": 1, "last_seen": event.get("timestamp"),
            "response_actions": [],
        }
        self.dedupe[key] = alert
        self.alerts.append(alert)
        self.alert_index[alert["alert_id"]] = alert
        return alert

    # ------------------------------------------------------------------ queries
    def set_status(self, alert_id: str, status: str, note: str = "") -> dict | None:
        with self.lock:
            a = self.alert_index.get(alert_id)
            if a:
                a["status"] = status
                a.setdefault("history", []).append({"at": now_iso(), "status": status, "note": note})
            return a

    def query(self, severity=None, min_severity=None, category=None, status=None, agent=None, user=None,
              repo=None, rule=None, session=None, q=None, limit=500) -> list[dict]:
        def ok(a):
            if severity and a["severity"] not in severity.split(","):
                return False
            if min_severity and SEVERITY_ORDER[a["severity"]] < SEVERITY_ORDER.get(min_severity, 0):
                return False
            if category and a["category"] not in category.split("|"):
                return False
            if status and a["status"] not in status.split(","):
                return False
            c = a["context"]
            if agent and c.get("agent") != agent:
                return False
            if user and c.get("user") != user:
                return False
            if repo and c.get("repo") != repo:
                return False
            if rule and a["rule_id"] != rule:
                return False
            if session and c.get("session_id") != session:
                return False
            if q:
                hay = " ".join([a["title"], a["rule_id"], a["category"], a["evidence"]["snippet"], str(c),
                                " ".join(t["technique_id"] for t in a["mitre"])]).lower()
                if q.lower() not in hay:
                    return False
            return True
        with self.lock:
            res = [a for a in reversed(self.alerts) if ok(a)]
        return res[:limit]

    def stats(self) -> dict:
        with self.lock:
            al = list(self.alerts)
            open_ = [a for a in al if a["status"] == "open"]
            acts = self.responder.actions if self.responder else []
            return {
                "started_at": self.started_at,
                "events_processed": sum(self.event_types.values()),
                "events_by_type": dict(self.event_types),
                "ingest_errors": len(self.errors),
                "sessions_seen": len(self.sessions),
                "alerts_total": len(al),
                "alerts_open": len(open_),
                "by_severity": dict(Counter(a["severity"] for a in al)),
                "open_by_severity": dict(Counter(a["severity"] for a in open_)),
                "by_category": dict(Counter(a["category"] for a in al).most_common()),
                "open_by_category": dict(Counter(a["category"] for a in open_).most_common()),
                "by_rule": dict(Counter(a["rule_id"] for a in al)),
                "by_agent": dict(Counter(a["context"]["agent"] for a in al)),
                "by_status": dict(Counter(a["status"] for a in al)),
                "blocked_sessions": list(self.responder.blocked_sessions.values()) if self.responder else [],
                "flagged_files": list(self.responder.flagged_files.values()) if self.responder else [],
                "response_actions_total": len(acts),
                "response_actions_by_type": dict(Counter(a["action"] for a in acts)),
                "webhook_status": dict(Counter(a["status"] for a in acts if a["action"] == "webhook")),
                "agents": sorted({e["agent"] for e in self.events if e.get("agent")}),
                "categories": sorted({r["category"] for r in RULES.values()}),
            }
