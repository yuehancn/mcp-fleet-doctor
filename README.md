# mcp-fleet-doctor

**Post-install operations for an MCP server fleet: what died, what silently grew, what carries risk.**

Paid. Local, read-only except for its own baseline file. No network calls.

---

## Why this exists when config linters already exist

A linter tells you what is wrong *right now*. The problems that actually cost you appear over months and never raise an error:

1. **Servers die quietly.** A package update, a moved path, a revoked token — the entry stays in the config, the agent silently loses a capability, and you find out weeks later when a task fails in a way you cannot explain. A fleet where 8 of 20 servers are dead is the normal steady state after a year.

2. **Tool schemas grow on every upgrade.** No protocol version warns you that a server went from 6 tools to 14. Every session now pays for the new schemas, in every request, forever. The agent gets worse and nothing in any log says why.

3. **Configuration risk accumulates as copy-paste.** Someone pastes a yolo flag from a blog post to make a demo work. Someone drops a key straight into `env` because the docs said so. Unpinned `npx` specs mean every restart may run different code.

None of these are caught by a one-shot check. They require a **recorded baseline** and a **repeatable measurement** — which is what this is.

## Install

Requires Python 3.8+. No dependencies.

```json
{
  "mcpServers": {
    "mcp-fleet-doctor": {
      "command": "python",
      "args": ["/absolute/path/to/mcp-fleet-doctor/run.py"]
    }
  }
}
```

## The workflow

```
1. record_baseline      # once, or after a deliberate upgrade
2. ...use your agent for a month...
3. diff_baseline        # did anything drift?
4. check_fleet          # full picture, when you need it
```

Running `check_fleet` without a baseline still gives you health and static risk, but the drift section — the part you are paying for — stays empty until you record one.

## Tools

### `check_fleet`
Starts every server, measures handshake latency and tool count, diffs against the baseline, audits the launch config, and returns a scored report with an ordered action list.

### `record_baseline`
Saves the current state as the reference point. The only operation that writes a file (to `~/.mcp-fleet-doctor/baseline.json`).

### `audit_config_only`
Static audit with no probing — safe in CI, or on a machine where starting arbitrary servers is not acceptable.

### `diff_baseline`
Only what changed, nothing else.

## What gets flagged

**Health**
- Server will not start (missing binary, crash on launch, no `tools/list` reply)
- Slow handshake (over 3s — paid on every session)

**Drift** (requires baseline)
- `grew` — tool count increased; new schemas are now in every prompt
- `went_down` — was working, now does not
- `new` / `disappeared` / `shrank`

**Static risk**
- `command_missing` — the binary in the config does not exist
- `literal_secret` — a credential pasted into `env` in plain text
- `risky_flag` — `--yolo`, `--dangerously-skip-permissions`, and similar
- `unpinned_package` — `npx`/`uvx` without a version pin
- `plaintext_remote` — remote server over `http://`
- `shell_execution` — `curl | sh`, `eval`, destructive `rm` in the launch args
- `config_drift` — the same server name declared differently across clients

## What it does not do

- **Does not scan the network.** It reads declared configs and the local files they point at. It is not a vulnerability scanner and does not claim to be.
- **Does not sandbox the servers it starts.** It launches them exactly as your client would, which is the point — but that means a malicious server is still malicious here. Run it against servers you chose to install.
- **Does not fix anything.** It never edits your configs. Every finding carries the fix as text because the decision to disable a capability should be yours.
- **Does not measure remote servers.** URL-based servers are reported as unprobed, never silently scored as healthy.
- **Tool count is the drift signal, not token cost.** Token estimation shifts when the estimator improves; a server gaining six tools is an unambiguous fact that will not produce phantom drift after an upgrade of this tool.

## Self-verification

```bash
python tests/selftest.py
```

26 checks. The negative half matters most: a clean, pinned, keyring-based config must produce **zero** findings. A hygiene tool that cries wolf gets ignored within a week, and then it is worse than nothing.

## Boundaries worth knowing

- If a server writes to stdout before answering, the JSON-RPC stream breaks. That is a bug in *that* server, and this tool reports it as `no tools/list reply`.
- Baselines are per-machine. They record tool counts and status, not secrets, so they are safe to commit — but comparing baselines across machines will show spurious `new`/`disappeared` entries.
- Timeout defaults to 20s per server. Raise it for servers that compile on launch.

## License

Commercial. One-time purchase or subscription as listed on the marketplace.