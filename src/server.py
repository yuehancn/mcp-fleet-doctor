"""MCP server entry: fleet doctor.

Post-install ops for people running many MCP servers: which are still alive,
which silently grew, which carry configuration risk. Writes exactly one file,
the baseline, and only when explicitly asked.
"""

import json
import os
import sys

from . import health, render, scan
from .protocol import serve

SERVER_NAME = "mcp-fleet-doctor"
SERVER_VERSION = "1.0.0"

INSTRUCTIONS = (
    "Operational health for an MCP server fleet. Answers three questions a "
    "config linter cannot: which servers no longer start, which silently grew "
    "their tool list since the last check, and which carry configuration risk "
    "(missing binaries, unpinned packages, secrets in env, confirmation-bypass "
    "flags). Record a baseline once, then check periodically - tool schemas "
    "grow on every server upgrade and degrade the agent with no error. Only "
    "writes its own baseline file, never the client configs."
)

TOOLS = [
    {
        "name": "check_fleet",
        "description": (
            "Full health and risk pass over every configured MCP server: starts "
            "each one, measures handshake latency, counts tools, compares to the "
            "recorded baseline, and audits the launch configuration for "
            "dead commands, unpinned packages, plaintext secrets and "
            "confirmation-bypass flags. Use after installing or upgrading "
            "servers, or when the agent feels slower than it used to. Reads "
            "configs; writes nothing."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "config": {
                    "type": "string",
                    "description": "Path to an MCP client config. Defaults to "
                                   "auto-discovery across Claude Desktop, "
                                   "Cursor, WorkBuddy and project configs.",
                },
                "baseline": {
                    "type": "string",
                    "description": "Override the baseline file location.",
                },
                "timeout": {
                    "type": "number",
                    "description": "Per-server probe timeout in seconds. Default 20.",
                    "default": 20,
                },
            },
        },
    },
    {
        "name": "record_baseline",
        "description": (
            "Probe every server and save the current tool counts and status as "
            "the baseline that later check_fleet runs compare against. Run this "
            "right after a deliberate upgrade so the next drift report is clean. "
            "This is the only operation that writes a file."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "config": {"type": "string",
                           "description": "Path to an MCP client config."},
                "baseline": {"type": "string",
                             "description": "Where to write the baseline."},
            },
        },
    },
    {
        "name": "audit_config_only",
        "description": (
            "Static-only audit with no probing: checks launch commands, "
            "arguments and env for dead binaries, unpinned package specs, "
            "plaintext secrets, risky flags and plaintext remote URLs. Fast and "
            "safe to run in CI or on a machine where starting servers is not "
            "acceptable."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "config": {"type": "string",
                           "description": "Path to an MCP client config."},
            },
        },
    },
    {
        "name": "diff_baseline",
        "description": (
            "Show only what changed since the recorded baseline, without the "
            "full report. Use for a quick 'did anything drift' answer."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "config": {"type": "string"},
                "baseline": {"type": "string"},
            },
        },
    },
]


def _load(explicit_config):
    """Resolve configs.

    An explicit path is authoritative: the user pointed at one file, so mixing
    in auto-discovered configs would double-count servers and produce a report
    about a fleet they never asked about.
    """
    from . import probe  # reuse the discovery helpers
    if explicit_config:
        return [c for c in probe.discover_configs([explicit_config])
                if c[0] == "explicit"]
    return probe.discover_configs(None)


def _all_servers(configs):
    """Flatten every (label, name, spec) triple across configs."""
    triples = []
    for label, _path, servers, _err in configs:
        for name, spec in (servers or {}).items():
            triples.append((label, name, spec))
    return triples


def _probe_all(configs, timeout):
    seen = {}
    for label, name, spec in _all_servers(configs):
        if name in seen:
            continue  # first declaration wins for probing
        seen[name] = health.probe(name, spec, timeout=timeout)
    return list(seen.values())


def _no_config_message():
    return ("No MCP client config found. Looked in Claude Desktop, Cursor, "
            "WorkBuddy and project-level locations. Pass 'config' with an "
            "explicit path.")


def tool_check_fleet(args):
    configs = _load(args.get("config"))
    if not configs:
        return _no_config_message()
    timeout = float(args.get("timeout") or 20)
    timeout = max(3.0, min(timeout, 120.0))

    records = _probe_all(configs, timeout)

    findings = []
    for label, _path, servers, err in configs:
        if servers is None:
            findings.append({"severity": "high", "kind": "unreadable_config",
                             "server": label, "detail": str(err),
                             "fix": "repair or remove the config file"})
            continue
        findings.extend(scan.scan_config(label, _path, servers)["findings"])
    cross = scan.cross_config_issues(_all_servers(configs))

    baseline = health.load_baseline(args.get("baseline"))
    diff = health.diff_against_baseline(records, baseline)

    payload = {
        "health": records,
        "findings": findings,
        "cross": cross,
        "diff": diff,
        "summary": scan.summarize(findings),
    }
    payload["actions"] = render.build_actions(records, findings, diff)
    return render.render(payload)


def tool_record_baseline(args):
    configs = _load(args.get("config"))
    if not configs:
        return _no_config_message()
    records = _probe_all(configs, 20.0)
    path = health.save_baseline(records, args.get("baseline"))
    ok = [r for r in records if r["status"] == "ok"]
    dead = [r for r in records if r["status"] in ("dead", "failed")]
    skipped = [r for r in records if r["status"] == "skipped"]
    lines = ["Baseline recorded: %s" % path,
             "  %d live, %d dead, %d unprobed" % (len(ok), len(dead), len(skipped))]
    if dead:
        lines.append("")
        lines.append("Recorded despite being dead. Fix them, then record again:")
        for d in dead:
            lines.append("  - %s: %s" % (d["name"], d["reason"][:70]))
    return "\n".join(lines)


def tool_audit_config_only(args):
    configs = _load(args.get("config"))
    if not configs:
        return _no_config_message()
    findings = []
    for label, path, servers, err in configs:
        if servers is None:
            findings.append({"severity": "high", "kind": "unreadable_config",
                             "server": label, "detail": str(err),
                             "fix": "repair or remove the config file"})
            continue
        findings.extend(scan.scan_config(label, path, servers)["findings"])
    cross = scan.cross_config_issues(_all_servers(configs))
    summary = scan.summarize(findings)
    if not findings and not cross:
        return ("Static audit clean. %d config(s), score %d/100, grade %s. "
                "No dead commands, no unpinned specs, no plaintext secrets, "
                "no bypass flags."
                % (len(configs), summary["score"], summary["grade"]))
    payload = {"health": [], "findings": findings, "cross": cross,
               "diff": {"has_baseline": False, "changes": []},
               "summary": summary,
               "declared_count": len(_all_servers(configs))}
    payload["actions"] = render.build_actions([], findings,
                                              {"has_baseline": False,
                                               "changes": []})
    return render.render(payload)


def tool_diff_baseline(args):
    configs = _load(args.get("config"))
    if not configs:
        return _no_config_message()
    baseline = health.load_baseline(args.get("baseline"))
    if not baseline.get("exists"):
        return ("No baseline at %s. Run record_baseline first."
                % baseline.get("path"))
    records = _probe_all(configs, 20.0)
    diff = health.diff_against_baseline(records, baseline)
    if not diff["changes"]:
        return "No drift since %s. %d server(s) unchanged." % (
            diff.get("recorded_at") or "baseline", len(records))
    order = {"went_down": 0, "grew": 1, "new": 2, "disappeared": 3, "shrank": 4}
    lines = ["Drift since %s:" % (diff.get("recorded_at") or "baseline"), ""]
    for c in sorted(diff["changes"], key=lambda d: order.get(d["kind"], 9)):
        lines.append("  [%s] %s: %s" % (c["kind"], c["server"], c["detail"]))
    grew = [c for c in diff["changes"] if c["kind"] == "grew"]
    if grew:
        lines.append("")
        lines.append("Growth means new tool schemas are now injected into every "
                     "prompt. Re-run check_fleet to see the new token cost.")
    return "\n".join(lines)


HANDLERS = {
    "check_fleet": tool_check_fleet,
    "record_baseline": tool_record_baseline,
    "audit_config_only": tool_audit_config_only,
    "diff_baseline": tool_diff_baseline,
}


def main():
    serve(SERVER_NAME, SERVER_VERSION, INSTRUCTIONS, TOOLS, HANDLERS)


if __name__ == "__main__":
    main()