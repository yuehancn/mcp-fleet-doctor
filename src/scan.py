"""Static risk scan of MCP server definitions.

Scope note: this is NOT a network scanner and NOT a sandbox. It reads the
declared launch configuration and the files on disk that it points at, and
reports patterns that historically precede incidents:

  - a server that will not start (dead weight in the config)
  - secrets pasted into env instead of referenced
  - yolo / auto-approve style flags that disable confirmation
  - unpinned package specs so every restart may run different code
  - shells, curl|bash and eval in the launch args
  - servers that can write outside the workspace

False positives are expensive here: a flagged-but-fine server makes the whole
hygiene report ignorable. Every check below therefore requires a specific
pattern, not a keyword.
"""

import json
import os
import re
import shutil

PINNED_RE = re.compile(r"@\d+\.\d+\.\d+|==\d|@sha256:|\.tgz$|\.whl$")
UNPINNED_RE = re.compile(r"^(npx|uvx|pipx)$")

SECRET_PATTERNS = [
    (re.compile(r"\b(sk|rk|pk)[-_][A-Za-z0-9]{16,}\b"), "OpenAI-style key"),
    (re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"), "GitHub token"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"), "Google API key"),
    (re.compile(r"\bglpat-[A-Za-z0-9_\-]{16,}\b"), "GitLab token"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key block"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}\b"), "inline bearer token"),
]

# Flags that expand what the agent may do without asking. Matched as whole
# tokens so that e.g. "--yolo-mode-description" does not trip it.
RISKY_ARG_PATTERNS = [
    (re.compile(r"^--?(yolo|dangerously-skip-permissions|skip-confirmation|"
                r"auto-approve|no-confirm|force|assume-yes|-y)$", re.I),
     "bypasses confirmation"),
    (re.compile(r"^--?(allow|enable)-(all|write|exec|shell|delete)$", re.I),
     "grants broad capability"),
    (re.compile(r"^--?(root|unsafe|no-sandbox)$", re.I), "disables isolation"),
]

SHELL_PATTERNS = [
    (re.compile(r"(curl|wget)\s+[^|]*\|\s*(ba)?sh"), "download-pipe-execute"),
    (re.compile(r"\beval\b"), "eval"),
    (re.compile(r"\brm\s+-rf\s+[/~]"), "destructive rm"),
]

# Env var names that are fine to have set by the client itself
BENIGN_ENV = re.compile(r"^(PATH|HOME|NODE_PATH|PYTHONPATH|LANG|LC_ALL|TZ|"
                        r"TMPDIR|TEMP|TMP|SystemRoot|USERPROFILE|APPDATA|"
                        r"LOCALAPPDATA|PROGRAMFILES.*|COMSPEC|PATHEXT)$", re.I)


def _looks_literal_secret(value):
    """Bound the checks: an env var that references another var is fine."""
    if not value or len(value) < 8:
        return None
    if re.search(r"\$\{?[A-Z_]+\}?|%[A-Z_]+%", value):
        return None
    for pattern, label in SECRET_PATTERNS:
        if pattern.search(value):
            return label
    return None


def scan_server(name, spec):
    """Return a list of findings for one server entry."""
    findings = []

    def add(severity, kind, detail, fix):
        findings.append({"severity": severity, "kind": kind, "server": name,
                         "detail": detail, "fix": fix})

    if not isinstance(spec, dict):
        add("high", "malformed_entry", "server entry is not an object",
            "rewrite the entry as an object with command/args")
        return findings

    is_remote = bool(spec.get("url")) or spec.get("type") in (
        "http", "sse", "streamable-http")

    if is_remote:
        url = str(spec.get("url") or "")
        if url.startswith("http://"):
            add("high", "plaintext_remote",
                "remote server over http:// - credentials and tool schemas "
                "travel in clear text",
                "switch the url to https://")
        elif url and not url.startswith("https://"):
            add("medium", "unusual_remote_scheme",
                "remote url is neither http nor https: %s" % url[:60],
                "confirm this is intended")

    cmd = spec.get("command")
    if not is_remote:
        if not cmd:
            add("high", "no_command",
                "stdio server declares no command",
                "add a command, or remove the entry")
        else:
            resolved = os.path.expandvars(os.path.expanduser(str(cmd)))
            if not (os.path.isfile(resolved) or shutil.which(resolved)):
                add("high", "command_missing",
                    "command not found: %s" % cmd,
                    "install it or remove the entry - it costs config "
                    "complexity and provides nothing")

    args = [str(a) for a in (spec.get("args") or [])]
    if cmd and UNPINNED_RE.match(os.path.basename(str(cmd))):
        # npx/uvx/pipx resolve a package at every start unless pinned
        package_args = [a for a in args if not a.startswith("-")]
        if package_args and not any(PINNED_RE.search(a) for a in package_args):
            add("medium", "unpinned_package",
                "runs %s without a version pin: %s"
                % (os.path.basename(str(cmd)), package_args[0][:50]),
                "pin the version so a restart cannot silently run new code")

    for arg in args:
        for pattern, why in RISKY_ARG_PATTERNS:
            if pattern.match(arg.strip()):
                add("high", "risky_flag",
                    "argument %r %s" % (arg, why),
                    "remove the flag and confirm actions interactively")
        for pattern, why in SHELL_PATTERNS:
            if pattern.search(arg):
                add("high", "shell_execution",
                    "argument contains %s: %r" % (why, arg[:80]),
                    "replace with a direct call to the intended tool")

    env = spec.get("env") or {}
    if isinstance(env, dict):
        for key, val in env.items():
            if BENIGN_ENV.match(str(key)):
                continue
            label = _looks_literal_secret(str(val))
            if label:
                add("high", "literal_secret",
                    "env %s holds what looks like a %s in plain text" % (key, label),
                    "reference it from the OS keyring or an env var the client "
                    "injects, not the config file")
            elif len(str(val)) > 32 and not re.search(r"[\\/\s]", str(val)) \
                    and not re.search(r"\$\{?[A-Z_]", str(val)):
                add("low", "long_opaque_env",
                    "env %s holds a 32+ char opaque string" % key,
                    "if this is a token, move it out of the config file")

    if is_remote and not (spec.get("headers") or spec.get("env")
                          or spec.get("auth")):
        add("info", "remote_without_auth",
            "remote server declares no headers or auth block",
            "confirm the endpoint is intentionally public")

    return findings


def scan_config(label, path, servers):
    """Scan every server in one config file."""
    findings = []
    for name, spec in (servers or {}).items():
        findings.extend(scan_server(name, spec))

    # Duplicate server names across configs are a separate class of problem and
    # are handled by the caller (it has the full set).
    return {"label": label, "path": path, "findings": findings,
            "server_count": len(servers or {})}


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def cross_config_issues(all_servers):
    """Problems only visible when looking at every config together."""
    issues = []
    by_name = {}
    for label, name, spec in all_servers:
        by_name.setdefault(name, []).append((label, spec))

    for name, entries in by_name.items():
        if len(entries) > 1:
            shapes = set()
            for _label, spec in entries:
                sig = json.dumps({
                    "c": str(spec.get("command") or spec.get("url") or ""),
                    "a": [str(a) for a in (spec.get("args") or [])],
                }, sort_keys=True)
                shapes.add(sig)
            if len(shapes) > 1:
                issues.append({
                    "severity": "medium", "kind": "config_drift", "server": name,
                    "detail": "same server name declared differently in %d configs"
                              % len(entries),
                    "fix": "make them identical, or rename so you know which "
                           "one is running",
                    "detail_extra": [l for l, _s in entries],
                })
    return issues


def summarize(findings):
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    score = 100 - counts["high"] * 25 - counts["medium"] * 8 - counts["low"] * 2
    return {
        "score": max(0, min(100, score)),
        "counts": counts,
        "grade": ("A" if score >= 90 else "B" if score >= 75 else
                  "C" if score >= 60 else "D" if score >= 40 else "F"),
    }