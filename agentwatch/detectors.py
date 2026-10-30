"""Detection rules for coding-agent activity.

Each rule is a function ``(event, ctx) -> list[finding]``. A finding is a plain dict that the
engine enriches into an alert. Rules are registered with the ``@rule`` decorator so they show
up in ``/api/rules`` and ``agentwatch rules`` automatically.

ctx = {"policy": dict}
"""
from __future__ import annotations

import fnmatch
import re

from .utils import (
    BIDI_RE, SEVERITY_ORDER, TAG_RE, added_lines, decode_tag_chars, extract_hosts, edit_distance,
    find_hidden_unicode, find_injections, find_secrets, first_semver_major, host_matches, is_ip,
    max_sev, norm_pkg, parse_install_commands, parse_manifest_additions, redact_value, snippet,
)

RULES: dict[str, dict] = {}
DETECTORS: list = []

ATLAS, ATTACK = "MITRE ATLAS", "MITRE ATT&CK"

CAT_PI = "Prompt Injection"
CAT_SECRET = "Secret Exposure in Generated Code"
CAT_LEAK = "Data Leakage via LLM Context"
CAT_SHELL = "Unauthorized Shell Execution"
CAT_EXFIL = "Data Exfiltration"
CAT_CRED = "Credential Access"
CAT_DEPCONF = "Dependency Confusion"
CAT_MALPKG = "Malicious / Hallucinated Package"
CAT_GIT = "Repository & CI/CD Tampering"
CAT_CFG = "Agent Configuration Tampering"
CAT_CHAIN = "Correlated Attack Chain"


def T(framework: str, tactic: str, tid: str, name: str) -> dict:
    return {"framework": framework, "tactic": tactic, "technique_id": tid, "technique_name": name}


def rule(rule_id: str, name: str, category: str, description: str, techniques: list[dict]):
    def deco(fn):
        RULES[rule_id] = {"rule_id": rule_id, "name": name, "category": category,
                          "description": description, "techniques": techniques}
        DETECTORS.append((rule_id, fn))
        return fn
    return deco


def finding(rule_id, severity, title, field, evidence, action, techniques=None, matched=None,
            confidence=0.8, file_path=None, **extra) -> dict:
    meta = RULES[rule_id]
    return {
        "rule_id": rule_id, "rule_name": meta["name"], "category": meta["category"],
        "severity": severity, "title": title, "confidence": round(confidence, 2),
        "mitre": techniques or meta["techniques"],
        "evidence": {"field": field, "snippet": evidence, "matched": matched or []},
        "recommended_action": action, "file_path": file_path, "extra": extra,
    }


def P(e: dict) -> dict:
    return e.get("payload") or {}


SHELL_TOOLS = {"terminal", "run_terminal_cmd", "run_command", "bash", "shell", "execute_command"}


def get_command(e: dict) -> str | None:
    p = P(e)
    if e.get("event_type") == "shell_command":
        return p.get("command")
    if e.get("event_type") == "tool_call" and p.get("tool") in SHELL_TOOLS:
        return p.get("input")
    return None


def get_git_command(e: dict) -> str | None:
    p = P(e)
    if e.get("event_type") == "git_operation":
        return " ".join(["git", p.get("command", "")] + [str(a) for a in p.get("args", [])])
    cmd = get_command(e)
    if cmd and re.search(r"(^|[;&|]\s*)git\s", cmd):
        return cmd
    return None


# ======================================================================================
# 1. Prompt injection (direct + indirect)
# ======================================================================================
UNTRUSTED_FIELDS = {"file_read": ["content_snippet"], "tool_call": ["output_snippet"],
                    "api_call": ["response_snippet"]}


@rule("PI-001", "Prompt injection in agent context", CAT_PI,
      "Detects instruction-override / concealment / exfiltration directives in content the agent ingests "
      "(fetched web pages, files, tool output) — indirect injection — or in the prompt itself (direct).",
      [T(ATLAS, "Initial Access", "AML.T0051.001", "LLM Prompt Injection: Indirect"),
       T(ATLAS, "Initial Access", "AML.T0051.000", "LLM Prompt Injection: Direct")])
def detect_prompt_injection(e, ctx):
    p, et, out = P(e), e["event_type"], []
    sources = []
    for f in UNTRUSTED_FIELDS.get(et, []):
        if p.get(f):
            origin = p.get("path") or p.get("url") or p.get("input") or p.get("tool") or et
            sources.append((f"payload.{f}", p[f], "indirect", origin))
    if et == "prompt" and p.get("text"):
        kind = "direct" if p.get("role", "user") == "user" else "indirect"
        sources.append(("payload.text", p["text"], kind, "user prompt"))
    for field, text, kind, origin in sources:
        smuggled = decode_tag_chars(text)
        hits = find_injections(text) + find_injections(smuggled)
        if not hits:
            continue
        has_action = any(h["action"] for h in hits)
        if kind == "indirect":
            sev = "critical" if has_action else "high"
            tech = [T(ATLAS, "Initial Access", "AML.T0051.001", "LLM Prompt Injection: Indirect")]
            action = (f"Stop the agent session and discard its pending tool calls. Treat '{origin}' as hostile "
                      "content: block the source, review every action the agent took after ingesting it, and "
                      "require human approval for tool use in this session.")
        else:
            sev = "medium"
            tech = [T(ATLAS, "Initial Access", "AML.T0051.000", "LLM Prompt Injection: Direct")]
            action = ("Review the user's intent (red-teaming vs. misuse). Confirm guardrails held and no tool "
                      "calls were executed as a result.")
        first = min(hits, key=lambda h: h["start"])
        ev = snippet(text, first["start"], first["start"] + len(first["match"]))
        if smuggled and "⟦hidden:" not in ev:
            ev += f"\n[decoded hidden tag-characters] {smuggled[:200]}"
        conf = min(0.55 + 0.15 * len(hits), 0.98)
        out.append(finding("PI-001", sev, f"{kind.capitalize()} prompt injection via {origin}"[:140], field, ev,
                           action, tech, [h["pattern"] for h in hits], conf,
                           file_path=p.get("path"), injection_kind=kind, origin=origin))
    return out


# ======================================================================================
# 2. Hidden / invisible unicode (ASCII smuggling, bidi "Trojan Source")
# ======================================================================================
@rule("PI-002", "Invisible unicode / ASCII smuggling", CAT_PI,
      "Flags zero-width, bidi-override and Unicode tag characters in prompts, model output, ingested "
      "content or code edits. These hide instructions from humans while remaining readable to LLMs.",
      [T(ATLAS, "Defense Evasion", "AML.T0051.001", "LLM Prompt Injection: Indirect"),
       T(ATTACK, "Defense Evasion (TA0005)", "T1027", "Obfuscated Files or Information")])
def detect_hidden_unicode(e, ctx):
    p, out = P(e), []
    fields = {"prompt": ["text"], "completion": ["text"], "file_read": ["content_snippet"],
              "file_edit": ["diff"], "tool_call": ["output_snippet"], "api_call": ["response_snippet"]}
    for f in fields.get(e["event_type"], []):
        text = p.get(f) or ""
        chars = find_hidden_unicode(text)
        if not chars:
            continue
        has_tags, has_bidi = bool(TAG_RE.search(text)), bool(BIDI_RE.search(text))
        sev = "high" if (has_tags or has_bidi) else "medium"
        kinds = sorted(set(chars))[:8]
        first = next(i for i, c in enumerate(text) if find_hidden_unicode(c))
        ev = snippet(text, first, first + 1, width=90)
        decoded = decode_tag_chars(text)
        if decoded and "⟦hidden:" not in ev:
            ev += f"\n[decoded hidden text] {decoded[:220]}"
        label = "Unicode tag smuggling" if has_tags else ("Bidi override (Trojan Source)" if has_bidi
                                                          else "Zero-width characters")
        out.append(finding(
            "PI-002", sev, f"{label} in {e['event_type'].replace('_', ' ')} ({len(chars)} hidden chars)",
            f"payload.{f}", ev,
            "Strip invisible characters at the ingestion layer, diff the file in a hex-aware viewer, and reject "
            "the change/content until a human has reviewed the decoded text.",
            matched=kinds, confidence=0.9 if has_tags else 0.7, file_path=p.get("path"),
            hidden_char_count=len(chars)))
    return out


# ======================================================================================
# 3. Secrets written into code by the agent (or emitted by the model)
# ======================================================================================
@rule("SEC-001", "Secret in AI-generated code", CAT_SECRET,
      "Scans lines the agent adds to files (and model completions) for live credentials: AWS keys, GitHub/"
      "Slack/Stripe tokens, private keys, JWTs, hardcoded passwords and connection strings.",
      [T(ATTACK, "Credential Access (TA0006)", "T1552.001", "Unsecured Credentials: Credentials In Files")])
def detect_secret_in_code(e, ctx):
    p, et = P(e), e["event_type"]
    if et == "file_edit":
        text, field = "\n".join(added_lines(p.get("diff", ""))), "payload.diff"
    elif et == "completion":
        text, field = p.get("text", ""), "payload.text"
    else:
        return []
    secrets = find_secrets(text)
    if not secrets:
        return []
    sev = max_sev(*[s["severity"] for s in secrets])
    types = sorted({s["type"] for s in secrets})
    first = min(secrets, key=lambda s: s["start"])
    where = p.get("path") or "model completion"
    masked = ", ".join(f"{s['type']} {redact_value(s['value'])}" for s in secrets[:4])
    return [finding(
        "SEC-001", sev, f"{', '.join(types)} written to {where}"[:140], field,
        snippet(text, first["start"], first["end"]),
        f"Block the commit/PR containing {where}. Revoke and rotate: {masked}. Replace with a secret-manager "
        "reference (e.g. env var / Vault) and purge it from git history if already committed.",
        matched=types, confidence=0.9 if sev == "critical" else 0.75, file_path=p.get("path"),
        secret_count=len(secrets))]


# ======================================================================================
# 4. Data leakage through the LLM context window
# ======================================================================================
SENSITIVE_CONTEXT_RX = [
    re.compile(r"(^|/)\.env(\.[a-z0-9]+)?$"), re.compile(r"(^|/)id_(rsa|ed25519|ecdsa|dsa)$"),
    re.compile(r"\.aws/credentials$"), re.compile(r"\.(pem|key|p12|pfx)$"),
    re.compile(r"(?i)(customer|patient|employee|payroll|pii|gdpr)[^/]*\.(csv|xlsx|json|parquet|sql)$"),
    re.compile(r"(?i)(dump|backup|export)[^/]*\.(sql|csv|bak)$"),
]
NOT_SENSITIVE_RX = re.compile(r"\.(example|sample|template|dist)$")


def is_sensitive_context(path: str) -> bool:
    path = (path or "").lower()
    return bool(path) and not NOT_SENSITIVE_RX.search(path) and any(r.search(path) for r in SENSITIVE_CONTEXT_RX)


@rule("LEAK-001", "Sensitive data sent to LLM", CAT_LEAK,
      "Inspects prompts leaving the developer machine: secrets in prompt text/attached context, sensitive "
      "files (.env, keys, customer exports) attached as context, and prompts sent to non-approved model "
      "endpoints (shadow AI).",
      [T(ATLAS, "Exfiltration", "AML.T0057", "LLM Data Leakage"),
       T(ATTACK, "Exfiltration (TA0010)", "T1567", "Exfiltration Over Web Service")])
def detect_llm_context_leak(e, ctx):
    if e["event_type"] != "prompt":
        return []
    p, pol = P(e), ctx["policy"]
    dest = (p.get("destination") or "").lower()
    approved = bool(host_matches(dest, pol["approved_llm_endpoints"])) if dest else True
    ctx_files = p.get("context_files") or []
    sensitive = [f for f in ctx_files if is_sensitive_context(f)]
    blob = (p.get("text") or "") + "\n" + (p.get("context_snippet") or "")
    secrets = find_secrets(blob)
    if not (secrets or sensitive or not approved):
        return []
    reasons = []
    if secrets:
        reasons.append(f"{len(secrets)} secret(s): " + ", ".join(sorted({s['type'] for s in secrets})))
    if sensitive:
        reasons.append("sensitive context files: " + ", ".join(sensitive))
    if not approved:
        reasons.append(f"non-approved model endpoint '{dest}'")
    if not approved and (secrets or sensitive):
        sev = "critical"
    elif secrets:
        sev = "high"
    else:
        sev = "medium"
    if secrets:
        s0 = min(secrets, key=lambda s: s["start"])
        ev = snippet(blob, s0["start"], s0["end"])
    else:
        ev = snippet(blob[:200], 0, 0)
    ev = f"destination={dest or 'n/a'} context_files={ctx_files}\n{ev}"
    action = []
    if secrets:
        action.append("rotate the exposed credentials (assume the provider has logged them)")
    if not approved:
        action.append(f"block egress to {dest} at the proxy and route the agent through the approved LLM gateway")
    if sensitive:
        action.append("add the sensitive paths to the agent's ignore list (.cursorignore / content exclusion)")
    return [finding("LEAK-001", sev, "Sensitive data in LLM context: " + "; ".join(reasons)[:120],
                    "payload", ev, ("Immediately " + ", ".join(action) + ".").capitalize(),
                    matched=reasons, confidence=0.85 if secrets else 0.7, destination=dest)]


# ======================================================================================
# 5. Unauthorized / dangerous shell execution
# ======================================================================================
# (name, regex, severity, technique)
SHELL_PATTERNS = [
    ("reverse shell (/dev/tcp)", re.compile(r"/dev/(tcp|udp)/"), "critical",
     T(ATTACK, "Execution (TA0002)", "T1059.004", "Command and Scripting Interpreter: Unix Shell")),
    ("netcat exec", re.compile(r"\b(nc|ncat|netcat)\b[^|;&]*\s-(e|c)\s"), "critical",
     T(ATTACK, "Command and Control (TA0011)", "T1059.004", "Command and Scripting Interpreter: Unix Shell")),
    ("pipe remote script to shell", re.compile(r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b"), "critical",
     T(ATTACK, "Execution (TA0002)", "T1059.004", "Command and Scripting Interpreter: Unix Shell")),
    ("decode-and-execute", re.compile(r"base64\s+(-d|--decode)[^|;&]*\|\s*(ba|z)?sh\b"), "critical",
     T(ATTACK, "Defense Evasion (TA0005)", "T1140", "Deobfuscate/Decode Files or Information")),
    ("python socket shell", re.compile(r"python3?\s+-c\s+.*socket.*(subprocess|pty|os\.dup2)"), "critical",
     T(ATTACK, "Execution (TA0002)", "T1059.006", "Command and Scripting Interpreter: Python")),
    ("destructive delete", re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?[a-zA-Z]*\s+(--no-preserve-root\s+)?(/|~|\$HOME|/\*)(\s|$)"),
     "critical", T(ATTACK, "Impact (TA0040)", "T1485", "Data Destruction")),
    ("shell profile persistence", re.compile(r">>?\s*~?/?[\w/.$]*\.(bashrc|zshrc|bash_profile|profile)\b"), "high",
     T(ATTACK, "Persistence (TA0003)", "T1546.004", "Event Triggered Execution: Unix Shell Configuration Modification")),
    ("cron persistence", re.compile(r"\bcrontab\b(?!\s+-l)|/etc/cron"), "high",
     T(ATTACK, "Persistence (TA0003)", "T1053.003", "Scheduled Task/Job: Cron")),
    ("history tampering", re.compile(r"\bhistory\s+-c\b|unset\s+HISTFILE|HISTFILE=/dev/null"), "high",
     T(ATTACK, "Defense Evasion (TA0005)", "T1070.003", "Indicator Removal: Clear Command History")),
    ("world-writable permissions", re.compile(r"\bchmod\s+(-R\s+)?0?777\b"), "medium",
     T(ATTACK, "Defense Evasion (TA0005)", "T1222.002", "File and Directory Permissions Modification")),
    ("privilege escalation (sudo)", re.compile(r"(^|[;&|]\s*)sudo\s"), "medium",
     T(ATTACK, "Privilege Escalation (TA0004)", "T1548.003", "Abuse Elevation Control Mechanism: Sudo")),
    ("security tool disablement", re.compile(r"\b(setenforce\s+0|ufw\s+disable|iptables\s+-F|systemctl\s+stop\s+\S*(falcon|defender|osquery|auditd))"),
     "high", T(ATTACK, "Defense Evasion (TA0005)", "T1562.001", "Impair Defenses: Disable or Modify Tools")),
    ("privileged container", re.compile(r"docker\s+run\b[^;&|]*--privileged|-v\s+/:/"), "high",
     T(ATTACK, "Privilege Escalation (TA0004)", "T1611", "Escape to Host")),
]
NETWORK_TOOLS_RX = re.compile(r"\b(curl|wget|nc|ncat|scp|rsync|ftp|nslookup|dig|Invoke-WebRequest)\b")


@rule("SH-001", "Dangerous shell command by agent", CAT_SHELL,
      "Matches high-risk command patterns executed by the agent (reverse shells, curl|bash, decode-and-execute, "
      "persistence, history wiping, destructive deletes, sudo). Severity is raised when the command was "
      "auto-executed without human approval. Also flags any non-allowlisted command run in auto-approve mode.",
      [T(ATTACK, "Execution (TA0002)", "T1059.004", "Command and Scripting Interpreter: Unix Shell")])
def detect_dangerous_shell(e, ctx):
    cmd = get_command(e)
    if not cmd:
        return []
    p, pol = P(e), ctx["policy"]
    approved = p.get("approved_by_user")
    hits = [(n, rx.search(cmd), s, t) for n, rx, s, t in SHELL_PATTERNS]
    hits = [(n, m, s, t) for n, m, s, t in hits if m]
    if hits:
        sev = max_sev(*[h[2] for h in hits])
        if approved is False and sev in ("medium", "high"):
            sev = {"medium": "high", "high": "critical"}[sev]
        hits.sort(key=lambda h: -SEVERITY_ORDER[h[2]])
        names = [h[0] for h in hits]
        techs = list({h[3]["technique_id"]: h[3] for h in hits}.values())
        m0 = hits[0][1]
        appr = "auto-executed without human approval" if approved is False else "approved by user" if approved else "approval unknown"
        return [finding(
            "SH-001", sev, f"Agent ran {' + '.join(names[:2])} ({appr})", "payload.command",
            snippet(cmd, m0.start(), m0.end(), width=160),
            "Kill the agent's terminal session and the spawned process tree, isolate the host if a reverse shell or "
            "remote script ran, check shell profiles/crontab for persistence, and disable auto-run (YOLO) mode for "
            "this agent.", techs, names, 0.9, approved_by_user=approved)]
    # Not obviously malicious: flag auto-executed commands outside the allowlist.
    if approved is False:
        allow = pol.get("shell_allowlist", [])
        stripped = cmd.strip()
        if NETWORK_TOOLS_RX.search(stripped) or re.match(r"(git|pip3?|npm|yarn|pnpm)\s", stripped):
            return []  # covered by exfil / dependency / git rules
        if not any(stripped.startswith(a) for a in allow):
            return [finding(
                "SH-001", "medium", "Non-allowlisted command auto-executed by agent", "payload.command",
                snippet(cmd, 0, 0, width=200),
                "Confirm the developer expected this command. Add it to the allowlist if legitimate, otherwise "
                "require approval for terminal tools in this agent's configuration.",
                matched=["outside shell allowlist", "auto-run"], confidence=0.5, approved_by_user=approved)]
    return []


# ======================================================================================
# 6. Data exfiltration over the network
# ======================================================================================
SENSITIVE_REF_RX = re.compile(
    r"(\benv\b\s*\||\bprintenv\b|\$\(?\s*env\b|\$\{?(AWS|GITHUB|GH|OPENAI|ANTHROPIC|NPM|SLACK|DB)_[A-Z_]*|"
    r"\.env\b|id_rsa|id_ed25519|\.aws/credentials|\.ssh/|\.git-credentials|\.npmrc|\.pypirc|\.kube/config|"
    r"/etc/(passwd|shadow)|-d\s*@|--data(-binary)?\s*@|--upload-file|-T\s|-F\s*['\"]?\w+=@)", re.I)
DNS_EXFIL_RX = re.compile(r"\b(nslookup|dig|host)\b[^;&|]*\$\(")


@rule("EXF-001", "Outbound data exfiltration", CAT_EXFIL,
      "Flags agent shell commands and HTTP tool calls that send data to paste sites, request bins, tunnels "
      "and other known exfil services, that ship credential files/env vars to untrusted hosts, DNS-tunnel "
      "data via command substitution, or push unusually large payloads off-network.",
      [T(ATTACK, "Exfiltration (TA0010)", "T1567", "Exfiltration Over Web Service"),
       T(ATLAS, "Exfiltration", "AML.T0025", "Exfiltration via Cyber Means")])
def detect_exfiltration(e, ctx):
    pol, p = ctx["policy"], P(e)
    if e["event_type"] == "api_call":
        url = p.get("url", "")
        text = f"{p.get('method', 'GET')} {url}\n{p.get('body_snippet', '')}"
        field, bytes_out = "payload.url/body_snippet", int(p.get("bytes_out") or 0)
        method = (p.get("method") or "GET").upper()
    else:
        text = get_command(e)
        if not text:
            return []
        field, bytes_out, method = "payload.command", 0, None
    hosts = extract_hosts(text)
    dns_exfil = bool(DNS_EXFIL_RX.search(text))
    sens = SENSITIVE_REF_RX.search(text) or (find_secrets(text) and re.search(r"\S", text))
    exfil_hosts = [h for h in hosts if host_matches(h, pol["exfil_domains"])]
    untrusted = [h for h in hosts if not host_matches(h, pol["trusted_domains"])
                 and not host_matches(h, pol["approved_llm_endpoints"])]
    reasons, sev, tech = [], None, None
    if dns_exfil:
        reasons.append("DNS query built from command substitution (DNS tunnelling)")
        sev = "critical"
        tech = [T(ATTACK, "Exfiltration (TA0010)", "T1048.003",
                  "Exfiltration Over Unencrypted Non-C2 Protocol (DNS)")]
    if exfil_hosts:
        reasons.append("known exfil/paste/tunnel service: " + ", ".join(exfil_hosts))
        sev = max_sev(sev or "info", "critical" if sens else "high")
    elif untrusted and sens and (method in (None, "POST", "PUT", "PATCH")):
        reasons.append("credential/env data sent to untrusted host: " + ", ".join(untrusted))
        sev = max_sev(sev or "info", "critical")
    elif e["event_type"] == "api_call" and untrusted and bytes_out > 500_000:
        reasons.append(f"{bytes_out:,} bytes uploaded to untrusted host {untrusted[0]}")
        sev = max_sev(sev or "info", "medium")
    if not sev:
        return []
    if sens and not dns_exfil:
        reasons.append("payload references sensitive data")
    anchor = text.find(exfil_hosts[0]) if exfil_hosts else (text.find(untrusted[0]) if untrusted else 0)
    return [finding(
        "EXF-001", sev, "Possible exfiltration: " + reasons[0][:110], field,
        snippet(text, max(anchor, 0), max(anchor, 0) + 40, width=160),
        "Block the destination at the egress proxy/DNS, kill the agent session, rotate any credentials the "
        "command referenced, and pull proxy logs for other traffic to the same host from this machine.",
        tech, reasons, 0.85, destinations=exfil_hosts or untrusted)]


# ======================================================================================
# 7. Credential / sensitive file access
# ======================================================================================
CRED_PATHS = [
    (re.compile(r"(~|\$HOME|/home/[^/\s]+|/Users/[^/\s]+|^)/?\.ssh/(id_[a-z0-9]+|[^\s/]+\.pem)(?!\.pub)\b"), "high",
     "SSH private key", T(ATTACK, "Credential Access (TA0006)", "T1552.004", "Unsecured Credentials: Private Keys")),
    (re.compile(r"\.aws/(credentials|config)\b"), "high", "AWS credentials file",
     T(ATTACK, "Credential Access (TA0006)", "T1552.001", "Unsecured Credentials: Credentials In Files")),
    (re.compile(r"\.(git-credentials|netrc|npmrc|pypirc)\b|\.docker/config\.json|\.kube/config\b"), "high",
     "developer credential store",
     T(ATTACK, "Credential Access (TA0006)", "T1552.001", "Unsecured Credentials: Credentials In Files")),
    (re.compile(r"/etc/shadow\b"), "critical", "/etc/shadow",
     T(ATTACK, "Credential Access (TA0006)", "T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow")),
    (re.compile(r"(Login Data|Cookies|key4\.db|logins\.json)\b"), "high", "browser credential store",
     T(ATTACK, "Credential Access (TA0006)", "T1555.003", "Credentials from Web Browsers")),
    (re.compile(r"(^|[\s/'\"=])\.env(\.(local|prod|production|staging|dev))?(?![\w.])"), "medium", ".env file",
     T(ATTACK, "Credential Access (TA0006)", "T1552.001", "Unsecured Credentials: Credentials In Files")),
]
READ_VERBS_RX = re.compile(r"\b(cat|less|more|head|tail|cp|scp|base64|xxd|strings|tar|zip|grep|awk|sed|curl|open)\b")


@rule("CRED-001", "Agent accessed credential material", CAT_CRED,
      "Detects the agent reading SSH keys, cloud credentials, token stores, /etc/shadow, browser credential "
      "stores or .env files — via file-read tools or shell commands. Coding tasks almost never need these.",
      [T(ATTACK, "Credential Access (TA0006)", "T1552", "Unsecured Credentials")])
def detect_credential_access(e, ctx):
    p, et = P(e), e["event_type"]
    if et == "file_read":
        text, field = p.get("path", ""), "payload.path"
    else:
        cmd = get_command(e)
        if not cmd or not READ_VERBS_RX.search(cmd):
            return []
        text, field = cmd, "payload.command"
    hits = [(rx.search(text), s, n, t) for rx, s, n, t in CRED_PATHS]
    hits = [h for h in hits if h[0]]
    if not hits:
        return []
    sev = max_sev(*[h[1] for h in hits])
    names = [h[2] for h in hits]
    techs = list({h[3]["technique_id"]: h[3] for h in hits}.values())
    m0 = hits[0][0]
    ev = snippet(text, m0.start(), m0.end(), width=160)
    if et == "file_read" and p.get("content_snippet"):
        ev += "\n[content] " + snippet(p["content_snippet"], 0, 0, width=120)
    return [finding(
        "CRED-001", sev, f"Agent read {names[0]}" + (" via shell" if et != "file_read" else ""), field, ev,
        f"Treat the {names[0]} as exposed: rotate it, confirm why the agent needed it, and add the path to the "
        "agent's deny-list / sandbox so it cannot be read again.",
        techs, names, 0.85, file_path=p.get("path"))]


# ======================================================================================
# 8. Dependency confusion
# ======================================================================================
def _collect_installs(e) -> list[dict]:
    p, et, out = P(e), e["event_type"], []
    if et == "package_install":
        eco = "npm" if p.get("manager") in ("npm", "yarn", "pnpm") else "pypi"
        out.append({"ecosystem": eco, "name": p.get("package", ""), "version": p.get("version", ""),
                    "index": p.get("registry", ""), "extra_indexes": p.get("extra_indexes", []),
                    "src": "payload.package", "raw": f"{p.get('manager')} install {p.get('package')}"
                    f"{'==' + p['version'] if p.get('version') else ''} (registry: {p.get('registry')})"})
    cmd = get_command(e)
    if cmd:
        for i in parse_install_commands(cmd):
            out.append({**i, "src": "payload.command", "raw": cmd})
    if et == "file_edit":
        for i in parse_manifest_additions(p.get("path", ""), p.get("diff", "")):
            out.append({**i, "extra_indexes": [], "src": "payload.diff", "raw": f"{p.get('path')}: {i['line']}"})
    return out


def _is_internal_name(name, pol):
    return any(name.lower().startswith(pfx) for pfx in pol["internal_package_prefixes"])


def _is_internal_registry(url, pol):
    return any(r in (url or "") for r in pol["internal_registries"])


@rule("DEP-001", "Dependency confusion risk", CAT_DEPCONF,
      "An internal-namespace package (e.g. mal-*, @mal/*) is resolved from a public registry, or pip is "
      "given --extra-index-url alongside the internal index (pip picks the highest version across indexes). "
      "Absurdly high versions (>= 50) are a classic squatting tell and escalate to critical.",
      [T(ATTACK, "Initial Access (TA0001)", "T1195.001",
         "Supply Chain Compromise: Compromise Software Dependencies and Development Tools"),
       T(ATLAS, "Initial Access", "AML.T0010", "AI Supply Chain Compromise")])
def detect_dependency_confusion(e, ctx):
    pol, out = ctx["policy"], []
    for i in _collect_installs(e):
        if not _is_internal_name(i["name"], pol) or i["index"] == "manifest":
            continue
        indexes = [i["index"]] + list(i.get("extra_indexes") or [])
        public = [x for x in indexes if x and not _is_internal_registry(x, pol)]
        if not public:
            continue
        major = first_semver_major(i.get("version", ""))
        sev = "critical" if (major is not None and major >= 50) else "high"
        why = (f"resolved from public registry {public[0]}" if not _is_internal_registry(i["index"], pol)
               else f"--extra-index-url {public[0]} lets a public package shadow the internal one")
        out.append(finding(
            "DEP-001", sev, f"Internal package '{i['name']}' {why}"[:140], i["src"],
            snippet(i["raw"], 0, 0, width=240),
            f"Do not run code from this install. Uninstall '{i['name']}', verify its origin/hash, pin the internal "
            "registry with scoped config (npm @mal:registry / pip --index-url only), and register the name as a "
            "placeholder on the public registry.",
            matched=[i["name"], i.get("version") or "unpinned", public[0]], confidence=0.85,
            package=i["name"], ecosystem=i["ecosystem"]))
    return out


# ======================================================================================
# 9. Malicious / typosquatted / hallucinated packages
# ======================================================================================
def _typosquat_target(name: str, popular: list[str]) -> str | None:
    n = norm_pkg(name)
    for pkg in popular:
        q = norm_pkg(pkg)
        if n == q:
            return None
        limit = 1 if len(q) <= 7 else 2
        if abs(len(n) - len(q)) <= limit and edit_distance(n, q) <= limit:
            return pkg
    return None


@rule("DEP-002", "Malicious, typosquatted or hallucinated package", CAT_MALPKG,
      "Checks every package the agent installs or adds to requirements.txt/package.json against a known-"
      "malicious list, edit-distance typosquat detection against popular packages, and a registry snapshot to "
      "catch hallucinated names (slopsquatting) that an attacker could register.",
      [T(ATTACK, "Initial Access (TA0001)", "T1195.001",
         "Supply Chain Compromise: Compromise Software Dependencies and Development Tools"),
       T(ATLAS, "Execution", "AML.T0011.001", "User Execution: Malicious Package")])
def detect_malicious_package(e, ctx):
    pol, out = ctx["policy"], []
    for i in _collect_installs(e):
        name, eco = i["name"], i["ecosystem"]
        if _is_internal_name(name, pol):
            continue
        n = norm_pkg(name)
        malicious = {norm_pkg(x) for x in pol["known_malicious_packages"].get(eco, [])}
        popular = pol["popular_packages"].get(eco, [])
        known = {norm_pkg(x) for x in popular + pol["registry_snapshot"].get(eco, [])}
        tech = None
        if n in malicious:
            sev, why, conf = "critical", "is on the known-malicious package list", 0.95
            tech = [T(ATTACK, "Initial Access (TA0001)", "T1195.001",
                      "Supply Chain Compromise: Compromise Software Dependencies and Development Tools"),
                    T(ATLAS, "Execution", "AML.T0011.001", "User Execution: Malicious Package")]
        elif n in known:
            continue
        elif (target := _typosquat_target(name, popular)):
            sev, why, conf = "high", f"looks like a typosquat of '{target}'", 0.8
        else:
            sev, why, conf = "medium", "was not found in the registry snapshot (possible hallucinated package)", 0.55
            tech = [T(ATLAS, "Resource Development", "AML.T0060", "Publish Hallucinated Entities"),
                    T(ATTACK, "Initial Access (TA0001)", "T1195.001",
                      "Supply Chain Compromise: Compromise Software Dependencies and Development Tools")]
        verb = "added to manifest" if i["index"] == "manifest" else "installed"
        out.append(finding(
            "DEP-002", sev, f"{eco} package '{name}' {verb}: {why}"[:150], i["src"],
            snippet(i["raw"], 0, 0, width=240),
            f"Remove '{name}' and block it in the package proxy. If it was installed, treat the environment as "
            "compromised (install scripts run with developer privileges): rebuild it and rotate local tokens. "
            "Ask the agent to cite an official source for any package it suggests.",
            tech, [name, why], conf, file_path=P(e).get("path") if i["index"] == "manifest" else None,
            package=name, ecosystem=eco))
    return out


# ======================================================================================
# 10. Git / CI tampering
# ======================================================================================
CI_PATH_RX = re.compile(r"(^|/)(\.github/workflows/|\.gitlab-ci\.yml$|Jenkinsfile$|\.circleci/|azure-pipelines\.yml$|"
                        r"bitbucket-pipelines\.yml$|\.buildkite/)")
CI_RISK = [
    (re.compile(r"\$\{\{\s*secrets\.[^}]+\}\}[^\n]*\b(curl|wget|nc)\b|\b(curl|wget)\b[^\n]*\$\{\{\s*secrets\."), "critical",
     "secrets piped to network tool"),
    (re.compile(r"\bpull_request_target\b"), "high", "pull_request_target trigger"),
    (re.compile(r"permissions:\s*write-all|contents:\s*write"), "medium", "broad write permissions"),
    (re.compile(r"\b(curl|wget)\b[^\n]*\|\s*(ba)?sh"), "critical", "remote script execution in pipeline"),
    (re.compile(r"toJSON\(\s*secrets\s*\)"), "critical", "dumps all secrets"),
]


def _branch_from_push(cmd: str) -> str | None:
    toks = [t for t in cmd.split() if not t.startswith("-")]
    try:
        i = toks.index("push")
    except ValueError:
        return None
    rest = toks[i + 1:]
    if len(rest) >= 2:
        ref = rest[-1]
        return ref.split(":")[-1].lstrip("+")
    return None


@rule("GIT-001", "Repository / CI tampering by agent", CAT_GIT,
      "Force-pushes to protected branches, --no-verify hook bypass, hooksPath changes, pushes to non-Mal "
      "remotes (source code exfiltration) and risky edits to CI/CD workflows (secrets to network, "
      "pull_request_target, curl|bash).",
      [T(ATTACK, "Impact (TA0040)", "T1565.001", "Data Manipulation: Stored Data Manipulation"),
       T(ATTACK, "Initial Access (TA0001)", "T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain")])
def detect_git_tampering(e, ctx):
    pol, p, out = ctx["policy"], P(e), []
    git = get_git_command(e)
    if git:
        prot = pol["protected_branches"]
        if re.search(r"\bpush\b", git) and re.search(r"(\s--force(-with-lease)?\b|\s-f\b|\s\+\S+)", git):
            br = _branch_from_push(git) or p.get("branch")
            if br and any(fnmatch.fnmatch(br, pat) for pat in prot):
                out.append(finding(
                    "GIT-001", "high", f"Force-push to protected branch '{br}'", "git", snippet(git, 0, 0, 200),
                    f"Restore '{br}' from the reflog/last known-good SHA, re-enable branch protection (no force "
                    "push) server-side, and review the overwritten commits.",
                    [T(ATTACK, "Impact (TA0040)", "T1565.001", "Data Manipulation: Stored Data Manipulation")],
                    ["force push", br], 0.9))
        if "--no-verify" in git or re.search(r"\bcommit\b[^;&|]*\s-n\b", git):
            out.append(finding(
                "GIT-001", "medium", "Agent bypassed git hooks with --no-verify", "git", snippet(git, 0, 0, 200),
                "Re-run the pre-commit hooks (secret scanning, lint) on the commit and enforce the same checks "
                "server-side in CI so client-side bypass has no effect.",
                [T(ATTACK, "Defense Evasion (TA0005)", "T1562.001", "Impair Defenses: Disable or Modify Tools")],
                ["--no-verify"], 0.8))
        if re.search(r"config\s+(--\w+\s+)?core\.hooksPath", git):
            out.append(finding(
                "GIT-001", "medium", "Agent changed core.hooksPath", "git", snippet(git, 0, 0, 200),
                "Reset core.hooksPath and inspect the new hooks directory for malicious scripts.",
                [T(ATTACK, "Persistence (TA0003)", "T1546", "Event Triggered Execution")], ["core.hooksPath"], 0.75))
        urls = re.findall(r"((?:https?://|git@)[^\s]+)", git) + ([p["remote_url"]] if p.get("remote_url") else [])
        for u in urls:
            norm = re.sub(r"^(https?://|git@)", "", u).replace(":", "/", 1)
            if not any(norm.startswith(t) for t in pol["trusted_git_remotes"]):
                out.append(finding(
                    "GIT-001", "high", f"Git remote outside Mal org: {norm[:80]}", "git", snippet(git, 0, 0, 200),
                    "Remove the remote, check whether code was pushed to it, and request takedown if source code "
                    "left the org. Enforce an egress allowlist for git hosts.",
                    [T(ATTACK, "Exfiltration (TA0010)", "T1567.001", "Exfiltration Over Web Service: Exfiltration to Code Repository")],
                    [norm], 0.8))
                break
    if e["event_type"] == "file_edit" and CI_PATH_RX.search(p.get("path", "")):
        text = "\n".join(added_lines(p.get("diff", "")))
        hits = [(rx.search(text), s, n) for rx, s, n in CI_RISK]
        hits = [h for h in hits if h[0]]
        sev = max_sev("medium", *[h[1] for h in hits]) if hits else "medium"
        m0 = hits[0][0] if hits else None
        out.append(finding(
            "GIT-001", sev, f"Agent modified CI/CD pipeline {p.get('path')}" + (f" ({hits[0][2]})" if hits else ""),
            "payload.diff", snippet(text, m0.start() if m0 else 0, m0.end() if m0 else 0, 160),
            "Require CODEOWNERS review for workflow files, block merge of this change, and rotate any secrets "
            "the modified workflow could reach if it has already run.",
            [T(ATTACK, "Initial Access (TA0001)", "T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain")],
            [h[2] for h in hits] or ["workflow modified"], 0.8 if hits else 0.5, file_path=p.get("path")))
    return out


# ======================================================================================
# 11. Agent configuration tampering ("rules file backdoor", auto-approve, rogue MCP servers)
# ======================================================================================
AGENT_CFG_RX = re.compile(r"(^|/)(\.cursorrules|\.cursor/rules/[^/]+|\.cursor/mcp\.json|\.github/copilot-instructions\.md|"
                          r"\.github/instructions/[^/]+|\.vscode/settings\.json|\.vscode/mcp\.json|mcp\.json|AGENTS\.md|"
                          r"CLAUDE\.md|\.windsurfrules|\.clinerules|\.aider\.conf\.yml|\.continue/config\.json)$")
AUTO_APPROVE_RX = re.compile(r"(?i)(autoApprove|auto_approve|alwaysAllow|yolo|dangerously-skip-permissions|"
                             r"\"?auto[_-]?run\"?\s*:\s*true|chat\.tools\.autoApprove|allowedCommands\"\s*:\s*\[\s*\"\*\")")
MCP_URL_RX = re.compile(r"\"(url|serverUrl|command)\"\s*:\s*\"([^\"]+)\"")


@rule("CFG-001", "Agent configuration tampering", CAT_CFG,
      "Edits to the agent's own instruction / rules / MCP / settings files. Escalates when the edit contains "
      "hidden unicode or injection phrasing (rules-file backdoor), enables auto-approval of tool calls, or "
      "registers an MCP server on an untrusted host.",
      [T(ATLAS, "Persistence", "AML.T0081", "Modify AI Agent Configuration"),
       T(ATTACK, "Defense Evasion (TA0005)", "T1562.001", "Impair Defenses: Disable or Modify Tools")])
def detect_agent_config_tamper(e, ctx):
    p = P(e)
    if e["event_type"] != "file_edit" or not AGENT_CFG_RX.search(p.get("path", "")):
        return []
    pol = ctx["policy"]
    raw = "\n".join(added_lines(p.get("diff", "")))
    reasons, sev, anchor = [], "low", 0
    if find_hidden_unicode(raw):
        reasons.append("hidden unicode in agent instructions")
        sev = "critical"
        anchor = next(i for i, c in enumerate(raw) if find_hidden_unicode(c))
    inj = find_injections(raw) + find_injections(decode_tag_chars(raw))
    if inj:
        reasons.append("injection phrasing: " + ", ".join(sorted({h['pattern'] for h in inj})))
        sev = "critical"
    m = AUTO_APPROVE_RX.search(raw)
    if m:
        reasons.append("enables auto-approval of agent tool calls")
        sev = max_sev(sev, "high")
        anchor = anchor or m.start()
    for mm in MCP_URL_RX.finditer(raw):
        hosts = extract_hosts(mm.group(2))
        bad = [h for h in hosts if not host_matches(h, pol["trusted_domains"])]
        if bad:
            reasons.append(f"registers MCP server on untrusted host {bad[0]}")
            sev = max_sev(sev, "high")
            anchor = anchor or mm.start()
    if not reasons:
        reasons.append("agent instruction/config file modified")
    decoded = decode_tag_chars(raw)
    ev = snippet(raw, anchor, anchor + 1, width=150) 
    if decoded and "⟦hidden:" not in ev:
        ev += f"\n[decoded hidden text] {decoded[:220]}"
    return [finding(
        "CFG-001", sev, f"{p.get('path')}: {reasons[0]}"[:140], "payload.diff", ev,
        "Revert the change to the agent configuration, require CODEOWNERS approval for agent rule/config files, "
        "and audit other repos for the same content (rules-file backdoors spread by copy-paste).",
        matched=reasons, confidence=0.9 if sev in ("critical", "high") else 0.5, file_path=p.get("path"))]


# ======================================================================================
# Correlation (stateful, run by the engine after per-event rules)
# ======================================================================================
RULES["CHAIN-001"] = {
    "rule_id": "CHAIN-001", "name": "Multi-stage agent hijack", "category": CAT_CHAIN,
    "description": "Session-level correlation: prompt injection followed by credential access and outbound "
                   "exfiltration (or by dangerous execution) in the same agent session — the signature of a "
                   "hijacked agent rather than a noisy one.",
    "techniques": [T(ATLAS, "Initial Access", "AML.T0051.001", "LLM Prompt Injection: Indirect"),
                   T(ATLAS, "Exfiltration", "AML.T0057", "LLM Data Leakage"),
                   T(ATTACK, "Exfiltration (TA0010)", "T1567", "Exfiltration Over Web Service")],
}

STAGE_OF = {"PI-001": "injection", "PI-002": "injection", "CFG-001": "injection", "CRED-001": "collection",
            "LEAK-001": "exfiltration", "EXF-001": "exfiltration", "SH-001": "execution"}
CHAINS = [
    ("injection→credential access→exfiltration", ["injection", "collection", "exfiltration"]),
    ("injection→dangerous execution", ["injection", "execution"]),
]


def correlate(session_state: dict, alerts: list[dict]) -> list[dict]:
    """Update per-session stage history with new alerts and emit chain findings once per chain."""
    out = []
    for a in alerts:
        stage = STAGE_OF.get(a["rule_id"])
        if stage and SEVERITY_ORDER[a["severity"]] >= SEVERITY_ORDER["medium"]:
            session_state.setdefault("stages", []).append((stage, a["alert_id"], a["evidence"]["event_id"]))
    stages = session_state.get("stages", [])
    fired = session_state.setdefault("chains_fired", set())
    for name, seq in CHAINS:
        if name in fired:
            continue
        idx, used = 0, []
        for st, aid, eid in stages:
            if idx < len(seq) and st == seq[idx]:
                used.append(f"{st}: {aid} ({eid})")
                idx += 1
        if idx == len(seq):
            fired.add(name)
            out.append({
                "rule_id": "CHAIN-001", "rule_name": RULES["CHAIN-001"]["name"], "category": CAT_CHAIN,
                "severity": "critical", "title": f"Hijacked agent session: {name}", "confidence": 0.95,
                "mitre": RULES["CHAIN-001"]["techniques"],
                "evidence": {"field": "session", "snippet": "\n".join(used), "matched": seq},
                "recommended_action": "Suspend the session and revoke the developer's active tokens (git, cloud, "
                                      "LLM gateway). Preserve the agent transcript for forensics, identify the "
                                      "injected source, and hunt for the same source in other sessions.",
                "file_path": None, "extra": {"chain": name, "linked_alerts": [u for u in used]},
            })
    return out
