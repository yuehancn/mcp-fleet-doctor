"""CLI entry point for mcp-fleet-doctor.

Two modes in one binary:
  serve                      speak MCP over stdio
  check / baseline / audit / diff   run one operation, print, exit

Exit-code contract matters here. `status` must exit 0 so WorkBuddy treats the
connector as ready. There are no credentials to check, so readiness is
unconditional; reporting "not authenticated" would leave the client polling
forever for a login that does not exist.
"""

import argparse
import json
import sys

__version__ = "1.0.0"


def _configs(explicit):
    from . import probe
    if explicit:
        return [c for c in probe.discover_configs([explicit]) if c[0] == "explicit"]
    return probe.discover_configs(None)


def _probe_all(configs, timeout=20.0):
    from . import health
    seen = {}
    for _label, _path, servers, _err in configs:
        for name, spec in (servers or {}).items():
            if name in seen:
                continue
            seen[name] = health.probe(name, spec, timeout=timeout)
    return list(seen.values())


def _fail_no_config():
    print("No MCP client config found. Pass --config with an explicit path.",
          file=sys.stderr)
    return 2


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="mcp-fleet-doctor",
        description="Health, drift and configuration risk for an MCP server "
                    "fleet. Writes only its own baseline file.",
    )
    parser.add_argument("--version", action="version",
                        version="%(prog)s " + __version__)
    sub = parser.add_subparsers(dest="cmd")

    p_serve = sub.add_parser("serve", help="run as an MCP server over stdio")

    p_check = sub.add_parser("check", help="full health and risk report")
    p_check.add_argument("--config")
    p_check.add_argument("--baseline")
    p_check.add_argument("--timeout", type=float, default=20.0)
    p_check.add_argument("--json", action="store_true")

    p_base = sub.add_parser("baseline", help="record the current state")
    p_base.add_argument("--config")
    p_base.add_argument("--baseline")

    p_audit = sub.add_parser("audit", help="static config audit, no probing")
    p_audit.add_argument("--config")
    p_audit.add_argument("--json", action="store_true")

    p_diff = sub.add_parser("diff", help="changes since the baseline")
    p_diff.add_argument("--config")
    p_diff.add_argument("--baseline")
    p_diff.add_argument("--json", action="store_true")

    p_status = sub.add_parser("status", help="report readiness (always ready)")
    p_status.add_argument("--json", action="store_true")
    sub.add_parser("unAuth", help="clear stored state")

    args = parser.parse_args(argv)

    if args.cmd == "serve":
        from .server import main as serve_main
        serve_main()
        return 0

    if args.cmd == "check":
        from . import health, render, scan
        configs = _configs(args.config)
        if not configs:
            return _fail_no_config()
        records = _probe_all(configs, args.timeout)
        findings = []
        for label, path, servers, err in configs:
            if servers is None:
                findings.append({"severity": "high", "kind": "unreadable_config",
                                 "server": label, "detail": str(err),
                                 "fix": "repair or remove the config file"})
                continue
            findings.extend(scan.scan_config(label, path, servers)["findings"])
        cross = scan.cross_config_issues(
            [(l, n, s) for l, _p, sv, _e in configs for n, s in (sv or {}).items()])
        diff = health.diff_against_baseline(
            records, health.load_baseline(args.baseline))
        payload = {"health": records, "findings": findings, "cross": cross,
                   "diff": diff, "summary": scan.summarize(findings)}
        payload["actions"] = render.build_actions(records, findings, diff)
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
            return 0
        print(render.render(payload))
        return 0

    if args.cmd == "baseline":
        from . import health
        configs = _configs(args.config)
        if not configs:
            return _fail_no_config()
        records = _probe_all(configs)
        path = health.save_baseline(records, args.baseline)
        ok = [r for r in records if r["status"] == "ok"]
        dead = [r for r in records if r["status"] in ("dead", "failed")]
        print("Baseline recorded: %s" % path)
        print("  %d live, %d dead" % (len(ok), len(dead)))
        for d in dead:
            print("  - %s: %s" % (d["name"], d["reason"][:70]))
        return 0

    if args.cmd == "audit":
        from . import render, scan
        configs = _configs(args.config)
        if not configs:
            return _fail_no_config()
        findings = []
        for label, path, servers, err in configs:
            if servers is None:
                findings.append({"severity": "high", "kind": "unreadable_config",
                                 "server": label, "detail": str(err),
                                 "fix": "repair or remove the config file"})
                continue
            findings.extend(scan.scan_config(label, path, servers)["findings"])
        cross = scan.cross_config_issues(
            [(l, n, s) for l, _p, sv, _e in configs for n, s in (sv or {}).items()])
        summary = scan.summarize(findings)
        if args.json:
            print(json.dumps({"findings": findings, "cross": cross,
                              "summary": summary}, ensure_ascii=False, indent=2))
            return 0
        if not findings and not cross:
            print("Static audit clean. %d config(s), score %d/100, grade %s."
                  % (len(configs), summary["score"], summary["grade"]))
            return 0
        payload = {"health": [], "findings": findings, "cross": cross,
                   "diff": {"has_baseline": False, "changes": []},
                   "summary": summary,
                   "declared_count": sum(len(sv or {}) for _l, _p, sv, _e in configs)}
        payload["actions"] = render.build_actions(
            [], findings, {"has_baseline": False, "changes": []})
        print(render.render(payload))
        return 0

    if args.cmd == "diff":
        from . import health
        configs = _configs(args.config)
        if not configs:
            return _fail_no_config()
        base = health.load_baseline(args.baseline)
        if not base.get("exists"):
            print("No baseline at %s. Run `baseline` first." % base.get("path"),
                  file=sys.stderr)
            return 2
        diff = health.diff_against_baseline(_probe_all(configs), base)
        if args.json:
            print(json.dumps(diff, ensure_ascii=False, indent=2))
            return 0
        if not diff["changes"]:
            print("No drift since %s." % (diff.get("recorded_at") or "baseline"))
            return 0
        order = {"went_down": 0, "grew": 1, "new": 2, "disappeared": 3, "shrank": 4}
        print("Drift since %s:" % (diff.get("recorded_at") or "baseline"))
        for c in sorted(diff["changes"], key=lambda d: order.get(d["kind"], 9)):
            print("  [%s] %s: %s" % (c["kind"], c["server"], c["detail"]))
        return 0

    if args.cmd == "status":
        payload = {"ready": True, "authRequired": False,
                   "detail": "no credentials needed; local read-only fleet audit"}
        if args.json:
            print(json.dumps(payload, ensure_ascii=False))
        else:
            print("Ready. This tool requires no authorization.")
        return 0

    if args.cmd == "unAuth":
        print("Nothing to clear: this tool stores no credentials. The baseline "
              "file is data, not authorization, and is left in place.")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())