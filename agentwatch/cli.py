"""AgentWatch CLI.

    python -m agentwatch.cli scan data/sample_agent_activity.ndjson [--min-severity high] [--category ...] [--json]
    python -m agentwatch.cli watch --url http://localhost:8080          # live terminal dashboard
    python -m agentwatch.cli rules                                       # list detection rules
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
import urllib.request
from collections import Counter

from .detectors import RULES
from .engine import Engine, load_policy
from .utils import SEVERITY_ORDER

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
SEV_COLOR = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m"}
DIM, BOLD, RESET = ("\033[2m", "\033[1m", "\033[0m") if USE_COLOR else ("", "", "")


def c(sev: str, text: str) -> str:
    return f"{SEV_COLOR.get(sev, '')}{text}{RESET}" if USE_COLOR else text


def bar(n: int, total: int, width: int = 28) -> str:
    filled = 0 if not total else max(1, round(width * n / total)) if n else 0
    return "█" * filled + "·" * (width - filled)


def render(stats: dict, alerts: list[dict], title: str, limit: int = 25) -> str:
    w = min(shutil.get_terminal_size((120, 40)).columns, 140)
    out = [f"{BOLD}{title}{RESET}", "─" * w]
    sev = stats.get("open_by_severity") or stats.get("by_severity", {})
    out.append(f"Events processed {stats['events_processed']}   Alerts {stats['alerts_total']} "
               f"(open {stats['alerts_open']})   " + "  ".join(
                   c(s, f"{s} {sev.get(s, 0)}") for s in ("critical", "high", "medium", "low")))
    out.append(f"Sessions contained {len(stats.get('blocked_sessions', []))}   Files flagged "
               f"{len(stats.get('flagged_files', []))}   Automated actions {stats.get('response_actions_total', 0)}"
               f"   Webhook {stats.get('webhook_status', {})}")
    out.append("")
    out.append(f"{BOLD}Alerts by category{RESET}")
    cats = stats.get("by_category", {})
    total = max(cats.values(), default=0)
    for cat, n in cats.items():
        out.append(f"  {cat:<38} {n:>3}  {bar(n, total)}")
    out.append("")
    out.append(f"{BOLD}Alert feed{RESET} {DIM}(newest first, {min(limit, len(alerts))} of {len(alerts)}){RESET}")
    out.append(f"  {'ID':<9} {'SEV':<9} {'RULE':<9} {'MITRE':<14} {'USER/AGENT':<30} TITLE")
    for a in alerts[:limit]:
        tech = a["mitre"][0]["technique_id"] if a["mitre"] else ""
        who = f"{(a['context']['user'] or '').split('@')[0]}/{a['context']['agent']}"
        title_w = max(20, w - 78)
        out.append(f"  {a['alert_id']:<9} {c(a['severity'], f'{a['severity']:<8}')} {a['rule_id']:<9} {tech:<14} "
                   f"{who[:29]:<30} {a['title'][:title_w]}")
    return "\n".join(out)


def cmd_scan(args):
    eng = Engine(load_policy(args.policy), output_dir=args.output, webhook_url=args.webhook,
                 respond=not args.no_respond)
    with open(args.file, encoding="utf-8") as f:
        results = eng.ingest_lines(f)
    if eng.responder:
        eng.responder.flush()
    alerts = eng.query(min_severity=args.min_severity, category=args.category)
    if args.json:
        print(json.dumps(alerts, indent=2, ensure_ascii=False))
    else:
        print(render(eng.stats(), alerts, f"AgentWatch scan: {args.file}", limit=args.limit))
        blocked = [r for r in results if r.get("decision") == "block"]
        if blocked:
            print(f"\n{BOLD}Inline enforcement:{RESET} {len(blocked)} event(s) received decision=block "
                  f"because their agent session was suspended: " + ", ".join(r["event_id"] for r in blocked[:8])
                  + (" …" if len(blocked) > 8 else ""))
        print(f"\n{DIM}Outputs written to {os.path.abspath(args.output)}/ "
              f"(alerts.ndjson, quarantine.ndjson, response_actions.ndjson, flagged_files.json, blocked_sessions.json){RESET}")
    if args.fail_on:
        worst = max((SEVERITY_ORDER[a["severity"]] for a in alerts), default=0)
        sys.exit(2 if worst >= SEVERITY_ORDER[args.fail_on] else 0)


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())


def cmd_watch(args):
    base = args.url.rstrip("/")
    try:
        while True:
            stats = _get(f"{base}/api/stats")
            q = f"?status=open&min_severity={args.min_severity or 'low'}"
            alerts = _get(f"{base}/api/alerts{q}")["alerts"]
            sys.stdout.write("\033[2J\033[H")
            print(render(stats, alerts, f"AgentWatch live: {base}   (Ctrl-C to exit)", limit=args.limit))
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    except OSError as ex:
        sys.exit(f"Cannot reach {base}: {ex}. Is the server running (docker compose up)?")


def cmd_rules(args):
    for r in RULES.values():
        techs = ", ".join(f"{t['technique_id']} ({t['framework'].split()[-1]})" for t in r["techniques"])
        print(f"{BOLD}{r['rule_id']:<10}{RESET}{r['name']}  [{r['category']}]\n          {techs}\n"
              f"          {DIM}{r['description']}{RESET}\n")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="agentwatch", description="Security monitoring for AI coding agents")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan an NDJSON log file and print the dashboard")
    s.add_argument("file")
    s.add_argument("--policy", default=None)
    s.add_argument("--output", default="output")
    s.add_argument("--webhook", default=os.environ.get("WEBHOOK_URL"))
    s.add_argument("--no-respond", action="store_true", help="detect only, skip automated responses")
    s.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default=None)
    s.add_argument("--category", default=None, help="exact category name (use | for several)")
    s.add_argument("--json", action="store_true", help="print alerts as JSON")
    s.add_argument("--limit", type=int, default=60)
    s.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default=None,
                   help="exit 2 if any alert at/above this severity (CI gate)")
    s.set_defaults(fn=cmd_scan)
    w = sub.add_parser("watch", help="live terminal dashboard against a running server")
    w.add_argument("--url", default="http://localhost:8080")
    w.add_argument("--interval", type=float, default=2.0)
    w.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default=None)
    w.add_argument("--limit", type=int, default=25)
    w.set_defaults(fn=cmd_watch)
    r = sub.add_parser("rules", help="list detection rules and MITRE mappings")
    r.set_defaults(fn=cmd_rules)
    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
