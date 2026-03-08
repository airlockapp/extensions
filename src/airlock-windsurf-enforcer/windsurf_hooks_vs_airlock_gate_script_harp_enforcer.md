# Windsurf Cascade Hooks — Spec Notes + HARP “Gate Script” Review

> **✅ STATUS: All bugs and gaps listed in this document have been implemented as of 2026-03-04.**
> See [`extension-gateway-hardening.md`](../../extension-gateway-hardening.md) for the full implementation reference.
>
> Fixed: D1 (tool_info.file_path), D2 (pre_read_code/pre_write_code), self-protection covers file_path, buildDescription handles all hook types.

This doc is meant to be **AI-friendly** for a vibe-coding agent to implement fixes.

---

## 1) What Windsurf “Cascade Hooks” are (spec recap)

### 1.1 hooks.json structure

Minimal structure:

```json
{
  "hooks": {
    "pre_run_command": [
      { "command": "node /abs/path/hooksGateScript.js", "show_output": true }
    ]
  }
}
```

Each hook entry supports:
- `command` *(string, required)* — shell command to run.
- `show_output` *(boolean, optional)* — show hook stdout/stderr in Cascade UI.
- `working_directory` *(string, optional)* — directory to run the command from (defaults to workspace root).

### 1.2 Hook events (12 total)

**Pre-hooks (can block via exit code 2):**
- `pre_read_code`
- `pre_write_code`
- `pre_run_command`
- `pre_mcp_tool_use`
- `pre_user_prompt`

**Post-hooks (cannot block; action already happened):**
- `post_read_code`
- `post_write_code`
- `post_run_command`
- `post_mcp_tool_use`
- `post_cascade_response`
- `post_cascade_response_with_transcript`
- `post_setup_worktree`

### 1.3 Input JSON schema (stdin payload)

All hooks receive JSON on **stdin** with common fields:
- `agent_action_name` *(string)* — event name above.
- `trajectory_id` *(string)* — conversation id.
- `execution_id` *(string)* — agent turn id.
- `timestamp` *(string, ISO 8601)* — trigger time.
- `tool_info` *(object)* — event-specific payload.

Event-specific shapes (the ones relevant for governance):

**pre_read_code / post_read_code**
```json
{ "agent_action_name": "pre_read_code", "tool_info": { "file_path": "/abs/or/relative/path" } }
```
Note: `file_path` can be a **directory** when Cascade reads recursively.

**pre_write_code / post_write_code**
```json
{
  "agent_action_name": "pre_write_code",
  "tool_info": {
    "file_path": "/path/to/file",
    "edits": [ { "old_string": "...", "new_string": "..." } ]
  }
}
```

**pre_run_command / post_run_command**
```json
{ "agent_action_name": "pre_run_command", "tool_info": { "command_line": "...", "cwd": "/path" } }
```

**pre_mcp_tool_use / post_mcp_tool_use**
```json
{
  "agent_action_name": "pre_mcp_tool_use",
  "tool_info": {
    "mcp_server_name": "github",
    "mcp_tool_name": "create_issue",
    "mcp_tool_arguments": { "...": "..." }
  }
}
```

**pre_user_prompt**
```json
{ "agent_action_name": "pre_user_prompt", "tool_info": { "user_prompt": "..." } }
```
Special rule: `show_output` **does not apply** to this hook.

**post_cascade_response**
```json
{ "agent_action_name": "post_cascade_response", "tool_info": { "response": "(markdown)" } }
```
Special rule: `show_output` **does not apply**.

**post_cascade_response_with_transcript**
```json
{ "agent_action_name": "post_cascade_response_with_transcript", "tool_info": { "transcript_path": "~/.windsurf/transcripts/{trajectory_id}.jsonl" } }
```
Special rule: `show_output` **does not apply**.

### 1.4 Exit code + output contract

- Exit `0` ⇒ success, operation continues.
- Exit `2` ⇒ **blocking error**. Cascade surfaces **stderr** to the agent.
  - Only **pre-hooks** can block.
  - Post-hooks cannot block (action already happened).
- Any other exit code ⇒ error, but operation continues.

Practical implication:
- To “gate” an action you must do it in **pre_*** hooks.
- Your hook should write a **plain-text** explanation to **stderr** when blocking.

---

## 2) Auto-Execution Modes (Disabled / Allowlist / Auto / Turbo) and how they relate to hooks

Windsurf has **terminal command auto-execution levels**:
- **Disabled**: all commands require manual approval.
- **Allowlist Only**: only allowlisted commands auto-execute.
- **Auto**: model auto-executes “safe” commands; risky ones ask.
- **Turbo**: auto-exec everything except denylisted commands.

How this likely interacts with hooks (important for HARP / Airlock):

1) **Auto-execution only changes whether Windsurf prompts the user before executing a terminal command.**
2) **Hooks are orthogonal governance controls.** When `pre_run_command` fires, your script can still block via exit code 2.
3) Therefore, your Airlock gate can enforce “approval required” **even in Turbo** by blocking until your out-of-band approver accepts.

⚠️ Important ambiguity / need to test:
- It is not explicitly documented whether `pre_run_command` triggers **before** Windsurf’s own user-confirm prompt, or only after the user approves.
- The safe assumption for enforcement is: **treat hooks as the last gate before execution**, and build your logic to be idempotent.

Recommended test matrix (quick manual):
- For each Auto-Execution level, attempt:
  - a benign command (`echo hi`)
  - a denylisted command (`rm` if denylisted)
  - an allowlisted command (`git status` if allowlisted)
- Observe whether `pre_run_command` is called:
  - when Cascade *proposes* the command
  - when the command *actually executes*

Regardless of those details: **blocking in `pre_run_command` should prevent execution**.

---

## 3) Review of the attached `hooksGateScript.js` (Airlock Hooks Gate)

### 3.1 What the script currently does

- Reads stdin as JSON.
- Infers `payload.event` from `payload.agent_action_name`.
- Normalizes `payload.tool_info` into:
  - `payload.command` (from `tool_info.command_line`)
  - `payload.cwd` (from `tool_info.cwd`)
  - `payload.serverName` (from `tool_info.mcp_server_name`)
  - `payload.toolName` (from `tool_info.mcp_tool_name`)
  - `payload.input` (from `tool_info.mcp_tool_arguments`)
- Determines event fallback:
  - if command+cwd ⇒ `pre_run_command`
  - else if serverName/toolName ⇒ `pre_mcp_tool_use`
  - else ⇒ `unknown`
- Sends an approval request to Airlock Gateway.
- Polls for a decision.
- **Allows** only on explicit approved decision.
- **Blocks** on:
  - parse errors
  - gateway errors
  - explicit reject
  - timeout

### 3.2 Alignment with Windsurf hooks spec (✅ / ⚠️ / ❌)

✅ **Exit code behavior**: blocking uses `process.exit(2)` and writes a plain-text message to stderr.

✅ **Reads stdin JSON**: correct high-level pattern.

✅ **Understands `agent_action_name`**: sets `payload.event = payload.agent_action_name` if missing.

⚠️ **Assumes only two “critical” event types**:
- It effectively gates:
  - terminal commands (`pre_run_command`)
  - MCP tool calls (`pre_mcp_tool_use`)
- It does **not** recognize / normalize:
  - `pre_read_code`
  - `pre_write_code`
  - `pre_user_prompt`

This is a policy mismatch if you intend to gate file access and edits.

❌ **Self-protection check misses the main file-path field used by Windsurf read/write hooks**

Windsurf read/write hooks use `tool_info.file_path`.

Current self-protection checks derive `filePath` from:
- `payload.path`, or
- `payload.input.path` / `payload.input.file_path`, or
- `payload.filePath`

…but the script does **not** map `tool_info.file_path` into any of those, so:
- A `pre_read_code` attempting to read `.windsurf/hooks.json` would not be detected by the PROTECTED rule.
- Same for `pre_write_code`.

This is likely the biggest concrete bug.

⚠️ **Fail-open when not configured**

If `AIRLOCK_GATEWAY_URL` or `AIRLOCK_ROUTING_TOKEN` are missing, it allows.
- This is convenient for “not set up yet”, but it’s not fail-closed.
- If you require strict governance, consider making this configurable:
  - `AIRLOCK_FAIL_OPEN_IF_UNCONFIGURED=true/false` (default maybe true for dev).

⚠️ **stderr / show_output considerations**

- The script logs a lot to stderr. That’s fine when `show_output` is true.
- But for `pre_user_prompt`, `show_output` is ignored by Windsurf; still, stderr becomes the blocker reason to the agent.

⚠️ **Working directory**

Windsurf supports `working_directory` in hooks.json. The gate script ignores it.
- That’s okay if you run by absolute path and don’t rely on cwd.
- But if you want the script’s behavior to match config, you could:
  - accept `working_directory` via env var, or
  - let hooks.json set it.

---

## 4) What should be considered “critical actions” for approval

If the product goal is: “critical actions are sent for approval to the user”, then the only hook events that can truly gate (block) are the **pre-hooks**:

### 4.1 Recommended gate coverage (single gate script)

1) **`pre_run_command`** (must-have)
- Terminal command execution (obvious critical surface).

2) **`pre_write_code`** (must-have)
- Prevent unapproved modifications to sensitive paths.
- You can also enforce “no edits to certain paths” (deny) vs “ask approval”.

3) **`pre_mcp_tool_use`** (must-have)
- MCP can create issues, deploy infra, edit GitHub, etc.

4) **`pre_read_code`** (high value)
- Prevent reading secrets (e.g., `.env`, keys, certs), compliance boundaries.

5) **`pre_user_prompt`** (optional, governance/policy)
- Block prompt injection patterns (e.g., attempts to exfiltrate secrets).
- Be cautious: overly strict prompt gating can harm UX.

Post hooks are best used for logging/telemetry, not gating.

---

## 5) Concrete corrections to make `hooksGateScript.js` fully spec-aligned

### 5.1 Normalize file paths for read/write hooks

Add a normalization step:
- If `payload.tool_info.file_path` exists, map it to a canonical `payload.filePath` (or reuse existing `filePath` variable).

Example logic:
- `payload.filePath = payload.filePath ?? payload.tool_info?.file_path ?? payload.path ?? payload.input?.file_path ?? payload.input?.path;`
- Also normalize slashes and lowercasing as you already do.

### 5.2 Recognize all pre-hooks explicitly

Your current inference sets `payload.event` to `unknown` for read/write/prompt hooks.
Instead:
- Prefer `agent_action_name` as the single source of truth.
- Only “infer” when `agent_action_name` is missing (should be rare).

### 5.3 Build consistent “action summary” per hook type

For the approval UI, include:

- `pre_run_command`:
  - `command_line`, `cwd`

- `pre_write_code`:
  - `file_path`
  - **diff summary** (NOT full file contents):
    - number of edits
    - first N characters of each old/new string

- `pre_read_code`:
  - `file_path` (or directory)

- `pre_mcp_tool_use`:
  - `mcp_server_name`, `mcp_tool_name`
  - `mcp_tool_arguments` redacted/truncated

- `pre_user_prompt`:
  - `user_prompt` truncated

### 5.4 Ensure self-protection covers all relevant paths

Update the PROTECTED check to consider:
- read/write: `tool_info.file_path`
- MCP tools that take `file_path` inside `mcp_tool_arguments`

### 5.5 Tighten policy knobs (recommended)

Add environment-driven policy controls so ops can tune behavior without code edits:

- `AIRLOCK_ENFORCE_EVENTS` (csv):
  - default: `pre_run_command,pre_write_code,pre_mcp_tool_use,pre_read_code`

- `AIRLOCK_FAIL_OPEN_IF_UNCONFIGURED`:
  - default: `true` (dev friendly)
  - production: `false`

- `AIRLOCK_MAX_PAYLOAD_BYTES`:
  - cap stdin size to avoid memory abuse

- `AIRLOCK_REDACT_PATTERNS`:
  - redact secrets in prompts / args before sending to gateway

### 5.6 Correct handling of timeouts

Current behavior:
- `readStdin()` waits up to `TIMEOUT_SECONDS+10` seconds if stdin never closes.

For hooks, stdin should close quickly. Consider:
- A **separate** fixed `STDIN_READ_TIMEOUT_MS` (e.g., 2000ms) to avoid delaying the hook pipeline.

---

## 6) Suggested “gate policy” rules (what to approve vs auto-allow)

The gate script can be smarter than “approve everything”. Recommended split:

### 6.1 Always require approval

- `pre_run_command` where command matches high-risk patterns:
  - `rm`, `del`, `format`, `sudo`, `chmod`, `chown`, `curl | sh`, package manager installs, shell redirections to sensitive files.

- `pre_write_code` for:
  - `.windsurf/**`
  - hook scripts
  - CI/CD pipelines (`.github/workflows`, `teamcity`, etc.)
  - secrets (`.env*`, `*.pem`, `*.key`)

- `pre_mcp_tool_use` for:
  - create/update/delete actions
  - deployment / infra actions

### 6.2 Auto-allow (still audited)

- `pre_read_code` for common safe source files, but require approval for:
  - `.env`, credentials folders, private keys, SSH config, cloud provider config.

- `pre_run_command` for allowlisted safe commands:
  - `git status`, `git diff`, `ls`, `cat` (non-sensitive), `npm test` (maybe).

Implementation pattern:
- A local allow/deny policy evaluated before contacting gateway.
- If allow ⇒ exit 0 quickly (fast path).
- If deny ⇒ exit 2 with a clear message.
- Else ⇒ send approval request to Airlock.

---

## 7) Hooks.json recommendation (single gate script for all hooks)

You said: **no per-hook script files** — all hooks handled by one gate script.

Recommended `.windsurf/hooks.json` baseline:

```json
{
  "hooks": {
    "pre_read_code": [
      { "command": "node /ABS/PATH/hooksGateScript.js", "show_output": true }
    ],
    "pre_write_code": [
      { "command": "node /ABS/PATH/hooksGateScript.js", "show_output": true }
    ],
    "pre_run_command": [
      { "command": "node /ABS/PATH/hooksGateScript.js", "show_output": true }
    ],
    "pre_mcp_tool_use": [
      { "command": "node /ABS/PATH/hooksGateScript.js", "show_output": true }
    ],
    "pre_user_prompt": [
      { "command": "node /ABS/PATH/hooksGateScript.js" }
    ]
  }
}
```

Notes:
- Don’t set `show_output` for `pre_user_prompt` (ignored anyway).
- Keep the gate fast; slow hooks degrade UX.

---

## 8) “Bug list” for the agent to fix (high priority first)

1) **BUG: Protected file detection fails for pre_read_code / pre_write_code**
   - because `tool_info.file_path` isn’t used.

2) **BUG/Gap: pre_read_code and pre_write_code aren’t treated as first-class events**
   - event inference doesn’t cover them; buildDescription doesn’t show them.

3) **Gap: No prompt gating path (pre_user_prompt)**
   - if you want it, add it; else ignore.

4) **Operational: fail-open when not configured**
   - make it configurable.

5) **DX: approval payload quality**
   - include rich summaries and truncation/redaction.

---

## 9) Minimal implementation sketch (for the vibe agent)

Key idea: normalize everything into a canonical internal structure.

```text
input = parse stdin JSON
hook = input.agent_action_name
info = input.tool_info

canonical = {
  hook,
  trajectoryId: input.trajectory_id,
  executionId: input.execution_id,
  timestamp: input.timestamp,

  filePath: info.file_path ?? info.path ?? info.filePath,
  commandLine: info.command_line,
  cwd: info.cwd,

  mcpServer: info.mcp_server_name,
  mcpTool: info.mcp_tool_name,
  mcpArgs: info.mcp_tool_arguments,

  userPrompt: info.user_prompt,
  edits: info.edits
}

// evaluate deny/allow rules
if isProtected(canonical) => deny(exit 2)
if isAutoAllow(canonical) => allow(exit 0)

// else => request Airlock approval
submitApproval(canonical)
pollDecision()
```

---

## 10) Bottom line

- The current gate script matches the general hook mechanism (stdin JSON + exit codes).
- It is **not fully aligned** with the hook payload schema for file read/write hooks.
- If you want “critical actions require approval”, you should wire the same script into:
  - `pre_read_code`, `pre_write_code`, `pre_run_command`, `pre_mcp_tool_use` (and optionally `pre_user_prompt`).
- Auto-Execution modes affect **Windsurf’s internal approval UX** for terminal commands, but the hook-based gate can still enforce approval even in Turbo.

---



## IMPORTANT SECURITY NOTE

Missing `AIRLOCK_GATEWAY_URL` and `AIRLOCK_ROUTING_TOKEN` (or their modern equivalents `AIRLOCK_PIPE_NAME` and `AIRLOCK_LOCAL_SECRET`) MUST be treated as **fail open**. The enforcer must never block actions if it isn't configured.
