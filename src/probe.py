"""Read MCP client configs and probe live servers for their real tools/list.

Why probe instead of parsing the config:
A config only tells you which command starts the server. The context cost lives
in the tool schemas that come back over the wire, and those are frequently not
what the README claims (version drift, feature flags, runtime-conditional
tools). Guessing from the config would produce a confident wrong number, so the
only honest method is to run the server and ask it.

Everything here is read-only: we start the server, list tools, then close
stdin so it exits.
"""

import json
import os
import queue
import shutil
import subprocess
import threading

# Config locations, in discovery order. Values are (client_label, path).
# Only documented public locations are touched; nothing is written back.
CLIENT_CONFIGS = [
    ("Claude Desktop", os.path.expandvars(r"%APPDATA%\Claude\claude_desktop_config.json")),
    ("Cursor", os.path.expandvars(r"%USERPROFILE%\.cursor\mcp.json")),
    ("Claude Code (project)", os.path.join(os.getcwd(), ".mcp.json")),
    ("WorkBuddy", os.path.expandvars(r"%USERPROFILE%\.workbuddy\mcp.json")),
    ("VS Code (workspace)", os.path.join(os.getcwd(), ".vscode", "mcp.json")),
]


def discover_configs(extra_paths=None):
    """Return list of (label, path, parsed_dict) for configs that exist."""
    found = []
    seen = set()
    for label, path in CLIENT_CONFIGS:
        if not path or not os.path.isfile(path):
            continue
        real = os.path.normcase(os.path.abspath(path))
        if real in seen:
            continue
        seen.add(real)
        try:
            with open(path, "r", encoding="utf-8-sig") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            found.append((label, path, None, "unreadable: %s" % exc))
            continue
        # Both "mcpServers" and "servers" appear in the wild
        servers = data.get("mcpServers") or data.get("servers") or {}
        if servers:
            found.append((label, path, servers, None))
    for path in (extra_paths or []):
        if not os.path.isfile(path):
            found.append(("explicit", path, None, "file not found"))
            continue
        try:
            with open(path, "r", encoding="utf-8-sig") as fh:
                data = json.load(fh)
            servers = data.get("mcpServers") or data.get("servers") or data
            found.append(("explicit", path, servers, None))
        except (OSError, json.JSONDecodeError) as exc:
            found.append(("explicit", path, None, "unreadable: %s" % exc))
    return found


def _resolve_command(cmd):
    """Return an executable path, or None if the command is not resolvable.

    This matters: a missing binary is the single most common reason a declared
    server contributes nothing to the budget. Reporting 'schema cost 0' for it
    would be wrong in a confusing direction, so callers surface it separately.
    """
    if not cmd:
        return None
    expanded = os.path.expandvars(os.path.expanduser(cmd))
    if os.path.isfile(expanded):
        return expanded
    return shutil.which(expanded)


def probe_server(name, spec, timeout=25.0):
    """Start one stdio MCP server and capture its tools/list result.

    Returns dict:
      status: "ok" | "skipped" | "failed"
      reason: human readable detail when not ok
      tools:  list of tool descriptors when ok
      transport: "stdio"
    """
    if not isinstance(spec, dict):
        return {"status": "failed", "reason": "server entry is not an object",
                "tools": [], "transport": "stdio"}

    if spec.get("url") or spec.get("type") in ("http", "sse", "streamable-http"):
        return {"status": "skipped", "tools": [], "transport": "remote",
                "reason": "remote transport (URL-based); context cost not probed"}

    cmd = spec.get("command")
    executable = _resolve_command(cmd)
    if not executable:
        return {"status": "failed", "tools": [], "transport": "stdio",
                "reason": "command not found on PATH: %r" % cmd}

    args = [str(a) for a in (spec.get("args") or [])]
    env = os.environ.copy()
    for key, val in (spec.get("env") or {}).items():
        env[str(key)] = str(val)

    try:
        proc = subprocess.Popen(
            [executable] + args,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, text=True, encoding="utf-8", errors="replace",
            bufsize=1,
        )
    except OSError as exc:
        return {"status": "failed", "tools": [], "transport": "stdio",
                "reason": "could not start: %s" % exc}

    # Drain stderr on a thread, otherwise a chatty server fills the pipe buffer
    # and deadlocks before it ever answers tools/list.
    stderr_buf = []
    def _drain():
        try:
            for line in proc.stderr:
                stderr_buf.append(line)
                if len(stderr_buf) > 200:
                    break
        except Exception:
            pass
    threading.Thread(target=_drain, daemon=True).start()

    lines = queue.Queue()
    def _reader():
        try:
            for line in proc.stdout:
                lines.put(line)
        except Exception:
            pass
    threading.Thread(target=_reader, daemon=True).start()

    def send(obj):
        try:
            proc.stdin.write(json.dumps(obj, ensure_ascii=False) + "\n")
            proc.stdin.flush()
        except (OSError, ValueError):
            pass

    send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": "2024-11-05",
                     "capabilities": {},
                     "clientInfo": {"name": "context-budget-audit",
                                    "version": "1.0"}}})
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})

    tools = None
    error = None
    deadline_hit = False
    import time
    end = time.time() + timeout
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
        if msg.get("id") == 2:
            if "error" in msg:
                error = msg["error"].get("message", "unknown error")
            else:
                tools = (msg.get("result") or {}).get("tools")
            break
    else:
        deadline_hit = True

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

    if tools is not None:
        return {"status": "ok", "tools": tools, "transport": "stdio",
                "reason": ""}
    if deadline_hit:
        reason = "no tools/list reply within %.0fs" % timeout
    elif error:
        reason = "server returned error: %s" % error
    else:
        reason = "server exited without answering tools/list"
    tail = "".join(stderr_buf[-3:]).strip()
    if tail:
        reason += " | stderr: " + tail[:200]
    return {"status": "failed", "tools": [], "transport": "stdio",
            "reason": reason}