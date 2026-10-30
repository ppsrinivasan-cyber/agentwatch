"""Shared helpers used by the detectors: secret scanning, redaction, prompt-injection
patterns, hidden-unicode handling, host extraction and package-command parsing.

Everything here is pure-Python stdlib so the tool runs anywhere with no installs.
"""
from __future__ import annotations

import ipaddress
import re
import shlex
from typing import Iterable

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def sev_gte(a: str, b: str) -> bool:
    return SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0)


def max_sev(*sevs: str) -> str:
    return max(sevs, key=lambda s: SEVERITY_ORDER.get(s, 0))


# --------------------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------------------
# (label, regex, value_group, severity, apply_placeholder_filter)
SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0, "critical", False),
    ("AWS Secret Access Key",
     re.compile(r"(?i)aws.{0,25}(?:secret|private).{0,25}?['\"=:\s]([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"),
     1, "critical", False),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), 0, "critical", False),
    ("Slack Token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), 0, "critical", False),
    ("Stripe Live Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}"), 0, "critical", False),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}"), 0, "high", False),
    ("Private Key Block",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
     0, "critical", False),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), 0, "high", False),
    ("Hardcoded Credential",
     re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)"
                r"\b\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"),
     1, "high", True),
    ("Connection String Password",
     re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]+:([^@\s]{4,})@"),
     1, "high", True),
]

PLACEHOLDER_RE = re.compile(
    r"(?i)(changeme|placeholder|your[_-]|<[^>]*>|\$\{|xxxx|\*\*\*|dummy|redacted|example|"
    r"os\.environ|getenv|process\.env|secrets\.)"
)


def find_secrets(text: str) -> list[dict]:
    """Return a list of {type, value, severity, start, end} for every secret-looking match."""
    if not text:
        return []
    found, seen = [], set()
    for label, rx, grp, sev, filt in SECRET_PATTERNS:
        for m in rx.finditer(text):
            value = m.group(grp) if grp else m.group(0)
            if filt and PLACEHOLDER_RE.search(m.group(0)):
                continue
            key = (label, value)
            if key in seen:
                continue
            seen.add(key)
            found.append({"type": label, "value": value, "severity": sev,
                          "start": m.start(), "end": m.end()})
    return found


def redact_value(v: str) -> str:
    if v.startswith("-----BEGIN"):
        return v  # the header itself is not secret; the body is masked by redact_text
    if len(v) <= 8:
        return "****"
    return f"{v[:4]}{'*' * min(len(v) - 8, 12)}{v[-4:]}"


LONG_B64_RE = re.compile(r"[A-Za-z0-9+/=_-]{40,}")


def redact_text(text: str) -> str:
    """Mask secret values (keep first/last 4 chars) and any long base64-ish blobs."""
    if not text:
        return text
    for s in sorted(find_secrets(text), key=lambda s: -len(s["value"])):
        text = text.replace(s["value"], redact_value(s["value"]))
    return LONG_B64_RE.sub(lambda m: m.group(0)[:6] + "…[redacted]", text)


# --------------------------------------------------------------------------------------
# Hidden unicode ("ASCII smuggling", bidi overrides, zero-width chars)
# --------------------------------------------------------------------------------------
HIDDEN_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")
TAG_RE = re.compile("[\U000e0000-\U000e007f]+")
BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")


def find_hidden_unicode(text: str) -> list[str]:
    return [f"U+{ord(m.group()):04X}" for m in HIDDEN_RE.finditer(text or "")]


def decode_tag_chars(text: str) -> str:
    """Unicode 'tag' characters (U+E0020–U+E007E) mirror ASCII and are invisible in most
    editors. Attackers use them to smuggle instructions to LLMs. Decode them."""
    out = []
    for run in TAG_RE.findall(text or ""):
        out.append("".join(chr(ord(c) - 0xE0000) for c in run if 0xE0020 <= ord(c) <= 0xE007E))
    return " ".join(o for o in out if o)


def reveal_hidden(text: str) -> str:
    """Make invisible characters visible for evidence snippets."""
    text = TAG_RE.sub(lambda m: "⟦hidden:" + "".join(
        chr(ord(c) - 0xE0000) for c in m.group(0) if 0xE0020 <= ord(c) <= 0xE007E) + "⟧", text or "")
    return HIDDEN_RE.sub(lambda m: f"⟦U+{ord(m.group()):04X}⟧", text)


# --------------------------------------------------------------------------------------
# Prompt injection
# --------------------------------------------------------------------------------------
# (name, regex, is_action) — "action" patterns instruct the agent to *do* something harmful
INJECTION_PATTERNS = [
    ("instruction override", re.compile(
        r"(?i)\b(ignore|disregard|forget|override)\b.{0,20}\b(all|any|the|your)?\s*(previous|prior|above|earlier|system)\s+"
        r"(instructions?|prompts?|rules|directions|context)"), False),
    ("role reassignment", re.compile(
        r"(?i)\byou are now\b.{0,30}\b(developer mode|dan|unrestricted|jailbroken|admin|root|a different)"), False),
    ("concealment from user", re.compile(
        r"(?i)\b(do not|don't|never|without)\b.{0,15}\b(tell|inform|mention|reveal|notify|alert|asking)\b.{0,15}\b(the )?user"),
     False),
    ("fake system/turn markers", re.compile(
        r"(?i)(<\|?\s*(system|im_start|im_end|endoftext)\s*\|?>|\[/?INST\]|<\s*/?\s*(system|instructions)\s*>|^\s*###\s*system)"),
     False),
    ("addressed to AI agents", re.compile(
        r"(?i)\b(ai|llm|coding)\s+(agents?|assistants?|models?)\b.{0,40}\b(reading|processing|parsing|that read|must|should)"),
     False),
    ("new instructions", re.compile(r"(?i)\b(new|updated|real|actual)\s+(system\s+)?instructions?\s*[:\-]"), False),
    ("exfiltration directive", re.compile(
        r"(?i)\b(send|post|upload|exfiltrate|transmit|forward|curl|copy|leak|share)(s|ing|ed)?\b.{0,60}"
        r"(credentials?|secrets?|tokens?|api[ _-]?keys?|\.env\b|ssh\s*keys?|id_rsa|\.aws|passwords?)"), True),
    ("tool-execution directive", re.compile(
        r"(?i)\b(run|execute|invoke)\b.{0,25}\b(the following|this)\s+(command|script|shell|code)"), True),
]


def find_injections(text: str) -> list[dict]:
    hits = []
    for name, rx, is_action in INJECTION_PATTERNS:
        m = rx.search(text or "")
        if m:
            hits.append({"pattern": name, "match": m.group(0), "start": m.start(), "action": is_action})
    return hits


# --------------------------------------------------------------------------------------
# Evidence snippets
# --------------------------------------------------------------------------------------

def snippet(text: str, start: int = 0, end: int | None = None, width: int = 110, max_len: int = 420) -> str:
    """Return a redacted, hidden-char-revealed window around [start, end)."""
    if text is None:
        return ""
    end = start if end is None else end
    a, b = max(0, start - width), min(len(text), end + width)
    s = text[a:b]
    s = ("…" if a > 0 else "") + s + ("…" if b < len(text) else "")
    s = reveal_hidden(redact_text(s))
    return s if len(s) <= max_len else s[:max_len] + "…"


# --------------------------------------------------------------------------------------
# Hosts / URLs
# --------------------------------------------------------------------------------------
URL_RE = re.compile(r"(?i)\b(?:https?|wss?|ftp)://(?:[^@\s/'\"`]+@)?([A-Za-z0-9.\-]+|\[[0-9a-f:]+\])")
NC_RE = re.compile(r"\b(?:nc|ncat|netcat|telnet)\s+(?:-[a-zA-Z]+\s+)*([A-Za-z0-9.\-]+)\s+\d{1,5}")
SCP_RE = re.compile(r"\b(?:scp|rsync)\b.*?\s[\w.\-]+@([A-Za-z0-9.\-]+):")
DNS_RE = re.compile(r"\b(?:nslookup|dig|host)\s+(?:[^\s]*\$\([^)]*\)[^\s]*|[^\s]+)")
DOMAIN_TAIL_RE = re.compile(r"([A-Za-z0-9\-]+\.[A-Za-z0-9.\-]+)\s*$")


def extract_hosts(text: str) -> list[str]:
    hosts = []
    for rx in (URL_RE, NC_RE, SCP_RE):
        hosts += [m.group(1).lower().strip(".") for m in rx.finditer(text or "")]
    for m in DNS_RE.finditer(text or ""):
        dm = DOMAIN_TAIL_RE.search(m.group(0))
        if dm:
            hosts.append(dm.group(1).lower().strip("."))
    return list(dict.fromkeys(h for h in hosts if h))


def host_matches(host: str, domains: Iterable[str]) -> str | None:
    host = (host or "").lower()
    for d in domains:
        d = d.lower()
        if host == d or host.endswith("." + d):
            return d
    return None


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------------------
# Edit distance for typosquat detection (optimal string alignment / Damerau-Levenshtein)
# --------------------------------------------------------------------------------------

def edit_distance(a: str, b: str) -> int:
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def norm_pkg(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


# --------------------------------------------------------------------------------------
# Package install parsing (shell commands + manifest diffs)
# --------------------------------------------------------------------------------------
PIP_RE = re.compile(r"\b(?:python3?\s+-m\s+)?pip3?\s+install\s+([^;&|]+)")
NPM_RE = re.compile(r"\b(npm|pnpm|yarn)\s+(?:install|i|add)\s+([^;&|]+)")
PIP_VALUE_OPTS = {"-i", "--index-url", "--extra-index-url", "-r", "--requirement", "-c", "--constraint",
                  "-e", "--editable", "-t", "--target", "--trusted-host", "-f", "--find-links"}


def _split(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd)
    except ValueError:
        return cmd.split()


def split_pip_spec(tok: str) -> tuple[str, str]:
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)(?:\[[^\]]*\])?\s*(?:[=<>!~]=?\s*([^;,\s]+))?", tok)
    return (m.group(1), m.group(2) or "") if m else ("", "")


def split_npm_spec(tok: str) -> tuple[str, str]:
    if tok.startswith("@"):
        parts = tok[1:].split("@", 1)
        return "@" + parts[0], parts[1] if len(parts) > 1 else ""
    parts = tok.split("@", 1)
    return parts[0], parts[1] if len(parts) > 1 else ""


def parse_install_commands(cmd: str) -> list[dict]:
    """Extract package installs from a shell command string."""
    out = []
    for m in PIP_RE.finditer(cmd or ""):
        toks = _split(m.group(1))
        index, extra, pkgs, skip = None, [], [], False
        for i, t in enumerate(toks):
            if skip:
                skip = False
                continue
            if t in PIP_VALUE_OPTS:
                val = toks[i + 1] if i + 1 < len(toks) else ""
                if t in ("-i", "--index-url"):
                    index = val
                elif t == "--extra-index-url":
                    extra.append(val)
                skip = True
                continue
            if t.startswith("--index-url="):
                index = t.split("=", 1)[1]
                continue
            if t.startswith("--extra-index-url="):
                extra.append(t.split("=", 1)[1])
                continue
            if t.startswith("-") or t in (".",) or "/" in t:
                continue
            name, ver = split_pip_spec(t)
            if name:
                pkgs.append((name, ver))
        for name, ver in pkgs:
            out.append({"ecosystem": "pypi", "name": name, "version": ver,
                        "index": index or "https://pypi.org/simple", "extra_indexes": extra})
    for m in NPM_RE.finditer(cmd or ""):
        toks = _split(m.group(2))
        registry, pkgs, skip = None, [], False
        for i, t in enumerate(toks):
            if skip:
                skip = False
                continue
            if t == "--registry":
                registry = toks[i + 1] if i + 1 < len(toks) else ""
                skip = True
                continue
            if t.startswith("--registry="):
                registry = t.split("=", 1)[1]
                continue
            if t.startswith("-"):
                continue
            name, ver = split_npm_spec(t)
            if name:
                pkgs.append((name, ver))
        for name, ver in pkgs:
            out.append({"ecosystem": "npm", "name": name, "version": ver,
                        "index": registry or "https://registry.npmjs.org", "extra_indexes": []})
    return out


def added_lines(diff: str) -> list[str]:
    """Lines added in a unified diff; if no diff markers are present, every line counts."""
    lines = (diff or "").splitlines()
    if any(l.startswith(("+", "-", "@@")) for l in lines):
        return [l[1:] for l in lines if l.startswith("+") and not l.startswith("+++")]
    return lines


def parse_manifest_additions(path: str, diff: str) -> list[dict]:
    path_l = (path or "").lower()
    out = []
    if re.search(r"requirements[^/]*\.txt$", path_l):
        for line in added_lines(diff):
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            name, ver = split_pip_spec(line)
            if name:
                out.append({"ecosystem": "pypi", "name": name, "version": ver, "index": "manifest", "line": line})
    elif path_l.endswith("package.json"):
        for line in added_lines(diff):
            m = re.match(r'\s*"(@?[A-Za-z0-9._\-/]+)"\s*:\s*"([^"]*)"', line)
            if m and m.group(1) not in ("name", "version", "main", "description", "license", "type", "test",
                                         "build", "start", "dev", "lint"):
                out.append({"ecosystem": "npm", "name": m.group(1), "version": m.group(2),
                            "index": "manifest", "line": line.strip()})
    return out


def first_semver_major(ver: str) -> int | None:
    m = re.search(r"(\d+)", ver or "")
    return int(m.group(1)) if m else None
