"""Minimal MCP stdio server framework. Standard library only.

MCP stdio transport: newline-delimited JSON-RPC 2.0 over stdin/stdout.
This module deliberately implements only what a local read-only audit tool
needs: initialize, tools/list, tools/call. No resources, no prompts.
"""

import json
import sys
import traceback

PROTOCOL_VERSION = "2024-11-05"


def _reply(msg):
    sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _ok(msg_id, result):
    _reply({"jsonrpc": "2.0", "id": msg_id, "result": result})


def _err(msg_id, code, message):
    _reply({"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": code, "message": message}})


def serve(server_name, server_version, instructions, tools, handlers):
    """Run the stdio loop.

    tools: list of MCP tool descriptors.
    handlers: dict mapping tool name -> callable(arguments_dict) -> str
    """
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            _err(None, -32700, "parse error")
            continue

        method = msg.get("method")
        msg_id = msg.get("id")
        # Notifications carry no id and must not be answered.
        is_notification = "id" not in msg

        if method == "initialize":
            _ok(msg_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": server_name, "version": server_version},
                "instructions": instructions,
            })
        elif method in ("notifications/initialized", "initialized"):
            pass
        elif method == "tools/list":
            _ok(msg_id, {"tools": tools})
        elif method == "tools/call":
            params = msg.get("params") or {}
            name = params.get("name")
            args = params.get("arguments") or {}
            fn = handlers.get(name)
            if fn is None:
                _err(msg_id, -32602, "unknown tool: %s" % name)
                continue
            try:
                text = fn(args)
                _ok(msg_id, {"content": [{"type": "text", "text": text}]})
            except Exception as exc:  # keep the server alive; report inside the result
                detail = "%s: %s" % (type(exc).__name__, exc)
                _ok(msg_id, {
                    "content": [{"type": "text",
                                 "text": "tool failed: " + detail}],
                    "isError": True,
                })
                if args.get("__debug"):
                    traceback.print_exc(file=sys.stderr)
        elif method == "ping":
            _ok(msg_id, {})
        elif method == "shutdown":
            _ok(msg_id, {})
            break
        else:
            if not is_notification:
                _err(msg_id, -32601, "method not found: %s" % method)