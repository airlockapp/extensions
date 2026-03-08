# Copilot hooks (VS Code) — spec summary + HARP/Airlock gate script audit

> **STATUS: All bugs and gaps listed in this document have been implemented as of 2026-03-04.**
> See [extension-gateway-hardening.md](../../extension-gateway-hardening.md) for the full implementation reference.
>
> Fixed: Bug A (hookSpecificOutput wrapper), Bug B (hookEventName routing), Bug C (correct hookEventName in envelope), Bug D (critical tools set), Bug E (fail-closed with AIRLOCK_STRICT).

> Goal: **one** gate script handles **all** hook events. Critical actions must be routed to a human approver. This doc is written to be “vibe-coding-agent friendly” (actionable, precise, copy/pasteable).

---

## 1) What “Copilot hooks” are (VS Code Agent Hooks)

VS Code “Agent hooks” run **external commands** at deterministic lifecycle points in an agent session. Hooks exchange JSON over **stdin (input)** and **stdout (output)**.

### 1.1 Hook config file format (VS Code)

A hook file is JSON with a `hooks` object keyed by event name. Each value is an array of hook entries.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "type": "command",
        "command": "node .github/hooks/gate.js",
        "timeout": 30,
        "env": {
          "AIRLOCK_GATEWAY_URL": "https://...",
          "AIRLOCK_ROUTING_TOKEN": "..."
        }
      }
    ]
  }
}
```

Hook entry properties (high-level):
- `type`: must be `"command"`
- `command`: default command (cross-platform)
- optional OS overrides: `windows`, `linux`, `osx`
- optional: `cwd`, `env`, `timeout` (seconds)

### 1.2 Hook lifecycle events (VS Code)

VS Code supports these hook events (as of the docs you referenced):
- `SessionStart`
- `UserPromptSubmit`
- `PreToolUse`
- `PostToolUse`
- `PreCompact`
- `SubagentStart`
- `SubagentStop`
- `Stop`

**Your current gate script is effectively a `PreToolUse` gate** (it reads tool name + tool input and decides allow/deny).

---

## 2) VS Code hook IO schema you must implement

### 2.1 Common input fields (every hook)

Every hook receives a JSON object with at least:

```json
{
  "timestamp": "2026-02-09T10:30:00.000Z",
  "cwd": "/path/to/workspace",
  "sessionId": "session-identifier",
  "hookEventName": "PreToolUse",
  "transcript_path": "/path/to/transcript.json"
}
```

### 2.2 Common output fields (all hooks)

Any hook may output:

```json
{
  "continue": true,
  "stopReason": "Security policy violation",
  "systemMessage": "Operation blocked by security hook"
}
```

**Exit codes:**
- exit `0` → VS Code parses stdout as JSON
- exit `2` → **blocking error** (stops processing; surfaced to model)
- other exits → warning; VS Code continues

### 2.3 PreToolUse input (VS Code)

`PreToolUse` adds:

```json
{
  "tool_name": "editFiles",
  "tool_input": { "files": ["src/main.ts"] },
  "tool_use_id": "tool-123"
}
```

### 2.4 PreToolUse output (VS Code) — IMPORTANT

To control tool execution, VS Code expects a **nested** object:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Destructive command blocked by policy",
    "updatedInput": { "files": ["src/safe.ts"] },
    "additionalContext": "User has read-only access to production files"
  }
}
```

Key points:
- `permissionDecision`: `"allow" | "deny" | "ask"`
- Priority rule (multiple hooks for same tool): **deny > ask > allow**
- `updatedInput` must match the tool’s expected schema (otherwise ignored)

---

## 3) GitHub Copilot “hooks” spec vs VS Code hooks spec (why you must be careful)

There are **multiple** “hooks” systems in the Copilot ecosystem:

1) **VS Code Agent Hooks** (your target docs page)
- supports `hookSpecificOutput` for `PreToolUse`
- supports `allow/ask/deny`

2) **GitHub Copilot CLI / Copilot coding agent hooks** (GitHub docs)
- uses `toolName` + `toolArgs` (JSON string)
- some docs state **only `deny` is processed** by that system

✅ Your script tries to support both shapes (`tool_name/tool_input` and `toolName/toolArgs`). That’s good.

⚠️ But your current **stdout output shape matches the GitHub docs**, not the VS Code docs.

---

## 4) Audit of `hooksGateScript.js` against the VS Code spec

### 4.1 What is correct / aligned

- Reads stdin JSON and parses it.
- Works as a standalone Node script.
- Implements a “fail closed” security posture on parse/gateway errors.
- Handles both payload styles:
  - VS Code-style: `tool_name`, `tool_input`
  - GitHub CLI-style: `toolName`, `toolArgs` (string)
- Uses stdout to return a decision and exits `0` (correct for VS Code).

### 4.2 Spec mismatches / bugs (must fix)

#### BUG A — Wrong stdout schema for VS Code `PreToolUse`

**Current behavior**
- On approve: prints

```json
{ "permissionDecision": "allow" }
```

- On deny: prints

```json
{ "permissionDecision": "deny", "permissionDecisionReason": "..." }
```

**Why it’s wrong**
- VS Code expects `permissionDecision` under `hookSpecificOutput` with `hookEventName: "PreToolUse"`.

**Fix**
Return this shape:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow"
  }
}
```

and

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "..."
  }
}
```

#### BUG B — `permissionDecision: "ask"` not supported in the current gate design

You currently implement **only allow/deny**.

But in VS Code, `ask` is a first-class option:
- `ask` means: VS Code shows a **native confirmation UI** to the user.

If your product requirement is “**all critical actions go to Airlock mobile approval**”, then you **should not rely on `ask`** for those actions.

Instead:
- for critical actions → route to Airlock and output `allow` or `deny` only (after the mobile decision)
- for non-critical actions → you may still use `ask` as a fallback if gateway unreachable / user wants local-only approvals

#### BUG C — `hookEventName` is ignored but should be enforced

The script assumes it’s handling `PreToolUse`. But your stated goal is **one script for all hooks**.

You must branch logic by:

```js
const event = payload.hookEventName;
```

and handle each event with its own output schema.

If you don’t, the script will silently behave incorrectly when used for:
- `SessionStart` (output should generally be context injection, not tool approval)
- `PostToolUse` (different output fields)
- `Stop` etc.

#### BUG D — Tool names in `buildDescription()` don’t match VS Code tool naming

VS Code examples show tools like `editFiles`, `createFile`, `runTerminalCommand`, `fetch`, etc.

Your script uses mixed tool names:
- `bash`, `run_terminal_cmd`, `execute_command`
- `str_replace_editor`, etc.

Ensure you map the **actual** VS Code Copilot `tool_name` values (e.g., `bash`, `editFiles`, `readFile`, `createFile`, etc.).

Action item:
- Add a “tool name normalization” layer.

---

## 5) Does hook behavior change with user Auto-Approve modes?

There are **two separate mechanisms**:

1) **VS Code tool approval UI**
- Users (or org policies) can enable “global auto-approve” (YOLO mode) or tool-specific auto-approval.

2) **Hooks**
- Hooks run deterministically and can:
  - `deny` → blocks the tool
  - `ask` → forces a prompt
  - `allow` → auto-approves

### Practical implications for Airlock/HARP

- If a user enables **global auto-approve**, VS Code may stop prompting the user for tool approvals.
- **Hooks still execute** (they are a separate, deterministic stage), and a hook can still return `deny`.

⚠️ Uncertainty:
- The docs are explicit about how hook decisions are merged across multiple hooks (`deny > ask > allow`).
- They are **not explicit** (in the VS Code docs page) about precedence between hook decisions and user YOLO mode.

**Recommended stance for an enforcer:**
- Treat Auto-Approve as *orthogonal* and assume some users may have it enabled.
- Enforce your control by:
  - using `PreToolUse` to gate critical tools
  - returning `deny` when not approved
  - never relying on the built-in VS Code prompt to satisfy your “mobile approval” requirement

---

## 6) Which hook events you should support in a single gate script

### 6.1 Minimal enforcement set (recommended)

#### A) `PreToolUse` — the enforcement gate
Use for: any operation that can change state or exfiltrate data.

Decide which tools are “critical” and require Airlock:
- `runInTerminal` / `runTerminalCommand`
- `fetch` (URL access)
- file writes: `editFiles`, `createFile`, `deleteFile`, `renameFile`
- git network ops: `gitPush`, `createPullRequest`, etc.
- task execution: `runTask`

**Non-critical examples** you might allow without Airlock:
- `readFile` / `view` operations
- local search / symbol lookup

#### B) `UserPromptSubmit` — prompt auditing (optional but valuable)
Use for:
- logging user intent
- blocking obvious policy violations early
- attaching `additionalContext` (e.g., “This repo contains production secrets — never exfiltrate”)

#### C) `PostToolUse` — post-action auditing + “result approval” for fetch-like tools
Use for:
- logging tool outputs for compliance
- optional post-checks (lint/tests) after edits

#### D) `Stop` — session report / audit flush
Use for:
- finalizing logs
- shipping compliance artifacts

### 6.2 Hook-by-hook output rules (single script routing)

Your script should behave like:

```txt
switch(hookEventName):
  PreToolUse    -> output: { hookSpecificOutput: { permissionDecision, ... } }
  PostToolUse   -> output: { decision?, reason?, hookSpecificOutput: { additionalContext? } }
  SessionStart  -> output: { hookSpecificOutput: { additionalContext? } }
  UserPromptSubmit -> output: { hookSpecificOutput: { additionalContext? } } or { continue:false,... }
  Stop          -> output: { continue:true } (or inject summary context)
  others        -> output: { continue:true }
```

---

## 7) Concrete corrections to `hooksGateScript.js`

### 7.1 Implement VS Code-correct output builders

Add these helpers:

```js
function outPreToolUse(decision, reason, updatedInput, additionalContext) {
  const payload = {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: decision,
    }
  };

  if (reason) payload.hookSpecificOutput.permissionDecisionReason = reason;
  if (updatedInput) payload.hookSpecificOutput.updatedInput = updatedInput;
  if (additionalContext) payload.hookSpecificOutput.additionalContext = additionalContext;

  process.stdout.write(JSON.stringify(payload) + "\n");
}

function outContinue(systemMessage) {
  const payload = { continue: true };
  if (systemMessage) payload.systemMessage = systemMessage;
  process.stdout.write(JSON.stringify(payload) + "\n");
}

function outStop(stopReason, systemMessage) {
  process.stdout.write(JSON.stringify({ continue: false, stopReason, systemMessage }) + "\n");
}
```

Then replace:
- `process.stdout.write(JSON.stringify({ permissionDecision: "allow" })...` → `outPreToolUse("allow")`
- `deny(...)` → `outPreToolUse("deny", ...)`

### 7.2 Route by `hookEventName` (single script for all hooks)

At the top after parsing input:

```js
const event = payload.hookEventName || payload.hook_event_name || "";

if (!event) {
  // safest: deny tool usage because we cannot understand context
  // but if you expect non-PreToolUse hooks, you can allow+log.
}

switch (event) {
  case "PreToolUse":
    return handlePreToolUse(payload);
  case "UserPromptSubmit":
    return handleUserPromptSubmit(payload);
  case "PostToolUse":
    return handlePostToolUse(payload);
  case "SessionStart":
  case "Stop":
  case "SubagentStart":
  case "SubagentStop":
  case "PreCompact":
  default:
    outContinue();
    return;
}
```

### 7.3 Normalize tool schema (avoid brittle tool name checks)

Create a canonical tool record:

```js
function normalizeTool(payload) {
  const toolName = payload.tool_name || payload.toolName || "";
  const toolInput = (payload.tool_input && typeof payload.tool_input === "object")
    ? payload.tool_input
    : (payload.toolArgs ? safeJsonParse(payload.toolArgs) : undefined);

  return { toolName, toolInput: toolInput || {} };
}
```

Then build policy rules based on **VS Code tool names** (don’t guess).

### 7.4 Make “critical tools” policy explicit

Put this in one place:

```js
const CRITICAL_TOOLS = new Set([
  "runInTerminal",
  "runTerminalCommand",
  "fetch",
  "runTask",
  "editFiles",
  "createFile",
  "deleteFile",
  "renameFile",
  "gitPush",
  "createPullRequest",
]);
```

Then:
- if critical → route to Airlock and return `allow/deny`
- else → return `allow`

### 7.5 Safer behavior for configuration failure (recommended toggle)

Currently:
- missing gateway URL/token → **allow**

That’s fine for dev onboarding, but for production enforcement you likely want:
- a strict mode env var:

```js
const STRICT = process.env.AIRLOCK_STRICT === "1";
if (STRICT && (!GATEWAY_URL || !ROUTING_TOKEN)) {
  outPreToolUse("deny", "Airlock is not configured. Tool usage blocked by policy.");
  return;
}
```

---

## 8) Suggested “gate script contract” for the mobile approver

Since you want to include “which hooks can be added to the gate script”, the easiest durable approach is:

- Always send a single, normalized **approval request envelope** regardless of hook type.
- Add a `hookEventName` field in the artifact payload.
- For `PreToolUse`, include:
  - tool name
  - tool input
  - workspace + repo
  - `tool_use_id`
  - a human-friendly `displayText`

Then return `permissionDecision` based on the mobile decision.

---

## 9) Quick checklist (for the agent that will implement fixes)

- [ ] Output shape for VS Code `PreToolUse` is nested under `hookSpecificOutput`.
- [ ] Adds routing by `hookEventName` to support multiple hooks in **one** script.
- [ ] Defines explicit `CRITICAL_TOOLS` set.
- [ ] Normalizes tool schema; doesn’t rely on non-VS Code tool names.
- [ ] Uses `tool_use_id` if present.
- [ ] Keeps fail-closed behavior for parse/gateway errors.
- [ ] Adds `AIRLOCK_STRICT` to control fail-open vs fail-closed when not configured.

---

## Appendix: What you should NOT do

- Don’t rely on VS Code’s built-in `ask` UI for “mobile approval required” paths.
- Don’t return top-level `{permissionDecision: ...}` in VS Code Agent Hooks; it won’t match the documented output structure.
- Don’t assume `toolArgs` is always a JSON string; VS Code uses `tool_input` object.



## IMPORTANT SECURITY NOTE

Missing `AIRLOCK_GATEWAY_URL` and `AIRLOCK_ROUTING_TOKEN` (or their modern equivalents `AIRLOCK_PIPE_NAME` and `AIRLOCK_LOCAL_SECRET`) MUST be treated as **fail open**. The enforcer must never block actions if it isn't configured.
