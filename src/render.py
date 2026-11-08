"""Report rendering for the fleet doctor.

Structure is deliberately the same every run so that users can diff two reports
and see what moved. Section order: verdict, drift, health, static risk, fixes.
"""

from . import scan

SEV_LABEL = {"high": "HIGH", "medium": "MED", "low": "LOW", "info": "INFO"}


def _pct(x):
    return "%.1f%%" % (x * 100)


def render(payload):
    lines = []
    health = payload.get("health") or []
    findings = payload.get("findings") or []
    summary = payload.get("summary") or scan.summarize(findings)
    diff = payload.get("diff") or {"has_baseline": False, "changes": []}

    ok = [h for h in health if h["status"] == "ok"]
    dead = [h for h in health if h["status"] == "dead"]
    failed = [h for h in health if h["status"] == "failed"]
    skipped = [h for h in health if h["status"] == "skipped"]

    # Static-only runs carry no probe results, so fall back to the server names
    # seen in the configs. Saying "0 servers" there would be a plain lie.
    declared = payload.get("declared_count")
    total_servers = declared if declared is not None else len(health)
    mode = "" if health else " (static audit, not probed)"

    lines.append("MCP fleet check -- %d server(s)%s" % (total_servers, mode))
    lines.append("")
    lines.append("  grade %s   score %d/100   live %d / dead %d / unprobed %d"
                 % (summary["grade"], summary["score"], len(ok),
                    len(dead) + len(failed), len(skipped)))
    if dead or failed:
        lines.append("  %d server(s) will not start. That is pure config debt:"
                     % (len(dead) + len(failed)))
        lines.append("  it adds failure surface and provides no tools.")
    if health and not ok:
        lines.append("  Nothing probed came back alive.")
    lines.append("")

    # ---- drift first: it is the reason to subscribe, so it leads
    lines.append("CHANGE SINCE BASELINE")
    if not diff.get("has_baseline"):
        lines.append("  no baseline recorded - run record_baseline first, then "
                     "this section")
        lines.append("  will show what each server upgrade silently added")
    elif not diff["changes"]:
        lines.append("  no change since %s" % (diff.get("recorded_at") or "?"))
    else:
        order = {"went_down": 0, "grew": 1, "new": 2, "disappeared": 3,
                 "shrank": 4}
        for c in sorted(diff["changes"], key=lambda d: order.get(d["kind"], 9)):
            lines.append("  [%s] %s: %s" % (c["kind"], c["server"], c["detail"]))
    lines.append("")

    # ---- health
    if health:
        lines.append("HEALTH")
        w = max([len(h["name"]) for h in health] + [6])
        for h in sorted(health, key=lambda d: (d["status"] != "ok", d["name"])):
            lat = ("%dms" % h["latency_ms"]) if h["latency_ms"] is not None else "-"
            if h["status"] == "ok":
                lines.append("  %-*s  ok       %-30s %3d tools"
                             % (w, h["name"], "handshake " + lat, h["tool_count"]))
            else:
                lines.append("  %-*s  %-8s %s" % (w, h["name"], h["status"],
                                                   h["reason"][:70]))
        slow = [h for h in ok if (h["latency_ms"] or 0) > 3000]
        if slow:
            lines.append("")
            lines.append("  Slow to answer (>3s). Every session pays this:")
            for h in sorted(slow, key=lambda d: -(d["latency_ms"] or 0)):
                lines.append("    %s: %dms" % (h["name"], h["latency_ms"]))
        lines.append("")

    # ---- static risk
    if findings:
        lines.append("STATIC RISK")
        for f in sorted(findings, key=lambda d: scan.SEVERITY_ORDER.get(d["severity"], 9)):
            lines.append("  [%s] %s - %s" % (SEV_LABEL.get(f["severity"], "?"),
                                             f["server"], f["detail"]))
            if f.get("fix"):
                lines.append("         fix: %s" % f["fix"])
        lines.append("")
    else:
        lines.append("STATIC RISK")
        lines.append("  none found in the declared configs")
        lines.append("")

    # ---- cross-config
    cross = payload.get("cross") or []
    if cross:
        lines.append("CONFIG DRIFT ACROSS CLIENTS")
        for c in cross:
            lines.append("  %s: %s" % (c["server"], c["detail"]))
            if c.get("detail_extra"):
                lines.append("         seen in: %s" % ", ".join(c["detail_extra"]))
        lines.append("")

    # ---- action list, only what actually applies
    actions = payload.get("actions") or []
    if actions:
        lines.append("DO THIS NEXT")
        for i, a in enumerate(actions, 1):
            lines.append("  %d. %s" % (i, a))
        lines.append("")

    return "\n".join(lines)


def build_actions(health, findings, diff):
    """Derive a short, ordered to-do list from what was actually found."""
    actions = []
    dead = [h["name"] for h in health if h["status"] in ("dead", "failed")]
    if dead:
        actions.append("Remove or fix %s - they start nothing, so the config "
                       "only adds risk." % ", ".join(dead[:4]))
    high = [f for f in findings if f["severity"] == "high"]
    if high:
        kinds = sorted({f["kind"] for f in high})
        actions.append("Clear the %d high finding(s): %s."
                       % (len(high), ", ".join(kinds)))
    if diff.get("changes"):
        grew = [c for c in diff["changes"] if c["kind"] == "grew"]
        if grew:
            actions.append("%d server(s) grew their tool list since baseline. "
                           "Re-measure context cost before adding more."
                           % len(grew))
    slow = [h for h in health if (h["latency_ms"] or 0) > 3000
            and h["status"] == "ok"]
    if slow:
        actions.append("%s answers in over 3s; consider whether it needs to be "
                       "loaded every session." % slow[0]["name"])
    if not actions:
        actions.append("Nothing to fix. Re-record the baseline after your next "
                       "server upgrade so drift stays detectable.")
    return actions