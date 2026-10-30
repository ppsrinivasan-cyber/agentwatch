# 5-minute demo walkthrough (screen recording script)

Record at 1440×900 or larger with Loom, OBS, or QuickTime. Upload to YouTube (Unlisted) or Google Drive
("Anyone with the link → Viewer") and **test the link in an incognito window**.

Before recording: `docker compose down -v && rm -rf output/*`, then have a terminal ready in the repo folder and
two browser tabs (http://localhost:8080 and http://localhost:9000) closed.

| Time | Show | Say (roughly) |
|---|---|---|
| 0:00–0:30 | README top section | "AgentWatch monitors AI coding agents (Copilot, Cursor, our internal assistant). It ingests agent activity logs, runs 11 detection rules across 10 agent-specific threat categories, maps every alert to MITRE ATT&CK and ATLAS, and responds automatically. Zero dependencies, one command." |
| 0:30–1:00 | Terminal: `docker compose up --build` | "Two containers: the monitor and a mock webhook standing in for Slack or a SOAR. On start it streams our sample log of 64 events across 11 agent sessions." |
| 1:00–1:45 | Dashboard at :8080 while events stream in | "Counts update live. The threat strip shows alerts per category; width is volume, the coloured edge is the severity mix. Click Prompt Injection to filter." Click a segment, then Clear filters. |
| 1:45–2:45 | Click **Hijacked agent session** (CHAIN-001), then click AW-00001 and AW-00004 | "This is the most important alert. Bob asked Cursor to read a third-party README. The README hides instructions, partly in invisible Unicode tag characters which we decode right here in the evidence. The agent then read his AWS credentials and posted them to webhook.site. Each step is its own alert with MITRE mapping; the correlation rule links them into one critical incident and suspends the session." Point at evidence, MITRE table, recommended action, automated responses. |
| 2:45–3:30 | Filter severity Critical, search `T1195` | "Supply chain: dependency confusion on an internal package with version 99 pulled through --extra-index-url, typosquats like 'reqeusts', a known-malicious 'colourama', and a package that doesn't exist at all, the classic hallucinated-package / slopsquatting risk." Then show the `.cursorrules` backdoor and the auto-approve settings change. |
| 3:30–4:10 | Mock webhook tab :9000; then terminal `ls output/ output/flags` and `cat output/blocked_sessions.json` | "Automated responses: high and critical alerts are posted to the webhook, quarantined with the redacted raw event, affected files are flagged, and critical alerts suspend the agent session." |
| 4:10–4:40 | Second terminal: `python3 scripts/stream_events.py --delay 0.2 --session-suffix=_live` | "The ingest API also returns a decision per event: allow, require approval, or block. An agent gateway can call this before running a tool. You can see the session flip to block after its first critical alert." |
| 4:40–5:00 | `docker compose exec agentwatch python -m agentwatch.cli watch` or `make test` | "There's also a CLI dashboard, 28 unit tests and a labelled evaluation: 100% of attack events caught with zero false positives on the benign events. Rules and allowlists are tunable in config/policy.json." |
