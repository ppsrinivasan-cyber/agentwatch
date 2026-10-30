"""Stream an NDJSON log into a running AgentWatch server, one event at a time, the way an
agent gateway / IDE plugin would. Prints the enforcement decision returned for each event.

    python scripts/stream_events.py --url http://localhost:8080 --file data/sample_agent_activity.ndjson --delay 0.5
"""
import argparse
import json
import time
import urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--url", default="http://localhost:8080")
ap.add_argument("--file", default="data/sample_agent_activity.ndjson")
ap.add_argument("--delay", type=float, default=0.5)
ap.add_argument("--session-suffix", default="", help="append to session ids so a re-stream is not deduplicated")
args = ap.parse_args()

ICON = {"allow": "  allow           ", "require_approval": "! require_approval", "block": "x block           "}
with open(args.file, encoding="utf-8") as f:
    for line in f:
        if not line.strip():
            continue
        e = json.loads(line)
        if args.session_suffix:
            e["session_id"] = f"{e.get('session_id')}{args.session_suffix}"
            e["event_id"] = f"{e['event_id']}{args.session_suffix}"
        req = urllib.request.Request(f"{args.url.rstrip('/')}/api/events", data=json.dumps(e).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            res = json.loads(r.read())["results"][0]
        alerts = ", ".join(res["alerts"]) or "-"
        print(f"{ICON.get(res['decision'], res['decision'])}  {e['event_id']:<12} {e['event_type']:<16} alerts: {alerts}")
        time.sleep(args.delay)
