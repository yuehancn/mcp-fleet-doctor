---
name: mcp-fleet-doctor
description: MCP 服务器集群的体检工具。排查起不来的服务器、升级后偷偷增加的工具数、以及配置里的安全风险。需先录制基线才能看漂移。
version: 1.0.0
author: Yuehan
---

# MCP 集群体检

所有操作通过 `mcp-fleet-doctor` 命令执行。本地只读工具（唯一会写的是它自己的基线文件），无需认证。

## 何时使用

- 用户反馈「装了 MCP 之后 agent 变慢/变笨」，怀疑某个服务器升级后变胖
- 想确认配置里的服务器是否还都活着
- 接手别人的 MCP 配置，想快速看清风险
- 定期巡检（建议每月一次）

## 核心工作流

```bash
# 1. 首次使用：录制基线（之后才有漂移可看）
mcp-fleet-doctor baseline

# 2. 过一段时间：只看变化
mcp-fleet-doctor diff

# 3. 需要完整画面时：全量体检
mcp-fleet-doctor check
```

**顺序很重要**：没有基线时 `check` 仍会给出健康与风险，但「变化」一节是空的。如果用户想看漂移却还没录制基线，先引导他执行 `baseline`。

## 可用命令

```bash
# 全量体检：健康 + 漂移 + 静态风险 + 下一步动作
mcp-fleet-doctor check
mcp-fleet-doctor check --json          # 机器可读
mcp-fleet-doctor check --show-tools 5  # 附带最贵的工具

# 录制/更新基线（唯一会写文件的操作）
mcp-fleet-doctor baseline

# 只看变化
mcp-fleet-doctor diff
mcp-fleet-doctor diff --json

# 纯静态审计，不启动任何服务器（适合 CI 或不便启动进程的环境）
mcp-fleet-doctor audit

# 指定配置与基线位置
mcp-fleet-doctor check --config /path/to/mcp.json --baseline /path/to/b.json
```

## 输出解读

**评分**：100 分制。每个 high 扣 25、medium 扣 8、low 扣 2。A ≥90，B ≥75，C ≥60，D ≥40，F <40。

**CHANGE SINCE BASELINE** —— 付费价值所在：

| 标记 | 含义 |
|---|---|
| `grew` | 工具数增加。新 schema 现在进入每次请求，这是 agent 变慢的隐形原因 |
| `went_down` | 之前能用，现在不行 |
| `new` / `disappeared` | 新增或移除的服务器 |
| `shrank` | 工具数减少 |

**静态风险类别**：

| kind | 含义 | 严重度 |
|---|---|---|
| `command_missing` | 配置里的命令不存在 | high |
| `literal_secret` | 密钥明文写在 env 里 | high |
| `risky_flag` | `--yolo` 等跳过确认的开关 | high |
| `plaintext_remote` | 远程服务器用 http:// 明文 | high |
| `shell_execution` | 启动参数里有 `curl \| sh`、`eval` | high |
| `unpinned_package` | `npx` 未锁版本，每次重启可能跑不同代码 | medium |
| `config_drift` | 同名服务器在不同客户端配置不一致 | medium |

## 处理原则

1. **`grew` 是重点，不是噪音。** 工具数增加意味着每次请求都要多付这些 schema 的 token，永远不会自愈。发现后应建议用户重测上下文成本。
2. **`command_missing` 优先处理。** 起不来的服务器提供零能力，只增加失败面。
3. **`--yolo` 这类不要替用户决定开关。** 报出风险并说明后果，由用户决定是否保留。
4. **基线是数据不是凭证。** `unAuth` 不会删基线，这是正确的——删了漂移历史就断了。
5. **不启动服务器的场景用 `audit`。** 它会跳过所有探针，只做静态检查。

## 常见错误

| 现象 | 原因 | 处理 |
|---|---|---|
| `No baseline at ...` | 还没录制基线 | 先跑 `mcp-fleet-doctor baseline` |
| 远程服务器显示 unprobed | URL 类服务器无法本地探测 | 属正常，不是错误 |
| 某服务器 dead 但用户说能用 | 命令依赖的环境变量在探针环境中不存在 | 让用户在 `env` 里补齐，或用 `audit` 跳过探测 |
| 基线里出现大量 `new` | 换了机器或基线文件不一致 | 基线是本机的，跨机器比较会误报 |