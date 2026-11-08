"""Fleet health probing and budget regression tracking.

Two jobs that no one-off config linter can do:

1. HEALTH - start each server, run initialize + tools/list, measure latency and
   record whether it actually answers. A fleet where 8 of 20 servers are dead
   is the normal steady state after a year, and nothing tells the user.

2. REGRESSION - store a baseline of token cost and tool count per server, then
   report what changed. Tool schemas grow silently on every server upgrade;
   the agent degrades without any error ever appearing.

Baseline lives in a small JSON file beside the tool. It is the only file this
package ever writes, and only when the user asks to record.
"""

import json
import os
import queue
import shutil
import subprocess
import threading
import time

# Baseline location. Precedence: explicit argument > MCP_FLEET_DOCTOR_BASELINE
# env var > ~/.mcp-fleet-doctor/baseline.json.
#
# The env var exists so a Connector's cli.json can point the baseline at a
# CLI-owned config directory via its `env` block, instead of the path being
# baked in. Documentation for the Connector scheme explicitly warns against
# hardcoding client directories, so the default stays under the user's home.
BASELINE_DEFAULT = os.environ.get(
    "MCP_FLEET_DOCTOR_BASELINE",
    os.path.join(os.path.expanduser("~"), ".mcp-fleet-doctor", "baseline.json"),
)


def _resolve(cmd):
    if not cmd:
        return None
    p = os.path.expandvars(os.path.expanduser(str(cmd)))
    return p if os.path.isfile(p) else shutil.which(p)


def probe(name, spec, timeout=20.0):
    """Start one server, measure handshake and tools/list.

    Returns dict with status, latency_ms, tool_count, tools, reason.
    """
    if not isinstance(spec, dict):
        return {"name": name, "status": "failed", "reason": "malformed entry",
                "latency_ms": None, "tool_count": 0, "tools": []}

    if spec.get("url") or spec.get("type") in ("http", "sse", "streamable-http"):
        return {"name": name, "status": "skipped", "latency_ms": None,
                "tool_count": 0, "tools": [],
                "reason": "remote transport - health not probed locally"}

    exe = _resolve(spec.get("command"))
    if not exe:
        return {"name": name, "status": "dead", "latency_ms": None,
                "tool_count": 0, "tools": [],
                "reason": "command not found: %r" % spec.get("command")}

    args = [str(a) for a in (spec.get("args") or [])]
    env = os.environ.copy()
    for k, v in (spec.get("env") or {}).items():
        env[str(k)] = str(v)

    started = time.time()
    try:
        proc = subprocess.Popen([exe] + args, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, encoding="utf-8", errors="replace",
                                env=env, bufsize=1)
    except OSError as exc:
        return {"name": name, "status": "dead", "latency_ms": None,
                "tool_count": 0, "tools": [],
                "reason": "could not start: %s" % exc}

    err_buf = []
    def _drain():
        try:
            for line in proc.stderr:
                err_buf.append(line)
                if len(err_buf) > 150:
                    break
        except Exception:
            pass
    threading.Thread(target=_drain, daemon=True).start()

    lines = queue.Queue()
    def _read():
        try:
            for line in proc.stdout:
                lines.put(line)
        except Exception:
            pass
    threading.Thread(target=_read, daemon=True).start()

    def send(obj):
        try:
            proc.stdin.write(json.dumps(obj, ensure_ascii=False) + "\n")
            proc.stdin.flush()
        except Exception:
            pass

    send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                     "clientInfo": {"name": "fleet-doctor", "version": "1.0"}}})
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})

    tools = None
    reason = ""
    latency_ms = None
    end = started + timeout
    while time.time() < end:
        try:
            raw = lines.get(timeout=max(0.05, end - time.time()))
        except queue.Empty:
            break
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if msg.get("id") == 1 and latency_ms is None:
            latency_ms = int((time.time() - started) * 1000)
        if msg.get("id") == 2:
            if "error" in msg:
                reason = "tools/list error: %s" % msg["error"].get("message", "?")
            else:
                tools = (msg.get("result") or {}).get("tools") or []
                if latency_ms is None:
                    latency_ms = int((time.time() - started) * 1000)
            break
    else:
        reason = "no reply within %.0fs" % timeout

    if tools is not None and latency_ms is None:
        latency_ms = int((time.time() - started) * 1000)

    try:
        proc.stdin.close()
    except Exception:
        pass
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

    if tools is None:
        tail = "".join(err_buf[-2:]).strip()
        if tail:
            reason = (reason + " | " + tail[:160]).strip(" |")
        # A server that exits cleanly but never answers is "dead", not "failed":
        # either way it contributes nothing, and the user's action is the same.
        return {"name": name, "status": "dead", "latency_ms": latency_ms,
                "tool_count": 0, "tools": [],
                "reason": reason or "no tools/list response"}

    return {"name": name, "status": "ok", "latency_ms": latency_ms,
            "tool_count": len(tools), "tools": tools, "reason": ""}


# ------------------------------------------------------------------ baseline

def load_baseline(path=None):
    path = path or BASELINE_DEFAULT
    if not os.path.isfile(path):
        return {"path": path, "exists": False, "servers": {}}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict) or "servers" not in data:
            return {"path": path, "exists": False, "servers": {},
                    "error": "baseline file is not in the expected shape"}
        data["path"] = path
        data["exists"] = True
        return data
    except (OSError, json.JSONDecodeError) as exc:
        return {"path": path, "exists": False, "servers": {},
                "error": "unreadable baseline: %s" % exc}


def save_baseline(records, path=None):
    """Record current measurements as the new baseline."""
    path = path or BASELINE_DEFAULT
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {
        "schema": 1,
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "servers": {
            r["name"]: {
                "tool_count": r["tool_count"],
                "status": r["status"],
                "latency_ms": r["latency_ms"],
            } for r in records
        },
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    return path


def diff_against_baseline(records, baseline):
    """Compare current probe results to the stored baseline.

    Tool count is used as the regression signal rather than token cost: token
    estimation shifts when the estimator improves, but a server gaining six
    tools is an unambiguous fact.
    """
    if not baseline.get("exists"):
        return {"has_baseline": False, "changes": []}
    old = baseline.get("servers") or {}
    changes = []
    for rec in records:
        prev = old.get(rec["name"])
        if prev is None:
            changes.append({
                "server": rec["name"], "kind": "new",
                "detail": "not in baseline (%s)" % rec["status"],
            })
            continue
        prev_count = prev.get("tool_count") or 0
        now_count = rec["tool_count"]
        if rec["status"] != "ok":
            changes.append({
                "server": rec["name"], "kind": "went_down",
                "detail": "was ok with %d tools, now %s"
                          % (prev_count, rec["status"]),
            })
        elif now_count > prev_count:
            changes.append({
                "server": rec["name"], "kind": "grew",
                "detail": "tools %d -> %d (+%d) - new schemas are now in every "
                          "prompt" % (prev_count, now_count, now_count - prev_count),
            })
        elif now_count < prev_count:
            changes.append({
                "server": rec["name"], "kind": "shrank",
                "detail": "tools %d -> %d (-%d)"
                          % (prev_count, now_count, prev_count - now_count),
            })
    current = {r["name"] for r in records}
    for name in old:
        if name not in current:
            changes.append({"server": name, "kind": "disappeared",
                            "detail": "in baseline but no longer configured"})
    return {"has_baseline": True,
            "recorded_at": baseline.get("recorded_at"),
            "changes": changes}