# Cursor Hooks (Agent) — spec summary + HARP gate script alignment

**Airlock Approver** (mobile app): [App Store](https://apps.apple.com/us/app/airlock-approver/id6760250865) · [Google Play](https://play.google.com/store/apps/details?id=com.airlockapp.io)

> **✅ STATUS: All bugs and gaps listed in this document have been implemented as of 2026-03-04.**
> See [`extension-gateway-hardening.md`](../../extension-gateway-hardening.md) for the full implementation reference.
>
> Fixed: Bug A (hook_event_name preferred), Bug B (file_path canonical), Bug C (tool_input JSON parse), Bug D (camelCase userMessage/agentMessage), Bug E (removed non-Cursor events), Bug F (self-protection covers file_path + tool_input string).

This doc is written for an AI coding agent to implement fixes quickly.

---

## 1) Cursor hooks configuration (hooks.json)

### 1.1 Where hooks.json can live + priority
Cursor loads hooks from multiple locations; higher-priority sources override lower ones (Enterprise → Team → Project → User). The working directory depends on which source the hook came from (project hooks run from the repo root; user hooks from `~/.cursor/`; etc.). ([cursor.com](https://cursor.com/docs/agent/hooks?utm_source=chatgpt.com))

### 1.2 hooks.json schema (config)
A hooks config is:

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [{ "command": "..." }],
    "beforeMCPExecution": [{ "command": "..." }],
    "beforeReadFile": [{ "command": "..." }],
    "afterFileEdit": [{ "command": "..." }],
    "beforeSubmitPrompt": [{ "command": "..." }],
    "stop": [{ "command": "..." }]
  }
}
```

The JSON Schema confirms:
- `version` must be `1`
- `hooks` maps hook names → arrays of `{ command: string }`
- no extra properties allowed ([unpkg.com](https://unpkg.com/cursor-hooks%40latest/schema/hooks.schema.json))

### 1.3 **Single gate script for all hooks** (your requirement)
This is fully compatible with the schema: point every event at the same executable.

**Example** (project-level):

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [{ "command": ".cursor/hooks/airlock-gate.sh" }],
    "beforeMCPExecution":  [{ "command": ".cursor/hooks/airlock-gate.sh" }],
    "beforeReadFile":      [{ "command": ".cursor/hooks/airlock-gate.sh" }],
    "afterFileEdit":       [{ "command": ".cursor/hooks/airlock-gate.sh" }],
    "beforeSubmitPrompt":  [{ "command": ".cursor/hooks/airlock-gate.sh" }],
    "stop":                [{ "command": ".cursor/hooks/airlock-gate.sh" }]
  }
}
```

⚠️ Important: Cursor docs warn that **project hooks** should reference paths relative to repo root like `.cursor/hooks/...` (not `./hooks/...`). ([cursor.com](https://cursor.com/docs/agent/hooks?utm_source=chatgpt.com))

---

## 2) Hook event payloads and responses (what your gate must speak)

Cursor passes JSON on stdin and expects JSON on stdout for “blocking” hooks.

### 2.1 Common payload fields
Most payloads include:
- `hook_event_name` (string) — the event name (e.g. `beforeShellExecution`) ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))
- `workspace_roots` (array of paths) ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))
- often `conversation_id`, `generation_id` ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))

### 2.2 beforeShellExecution
**Payload (stdin)** includes at least:
- `command` (string)
- `cwd` (string)
- `hook_event_name: "beforeShellExecution"` ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))

**Response (stdout)** accepted format:
```json
{
  "continue": true,
  "permission": "allow|deny|ask",
  "userMessage": "...",
  "agentMessage": "..."
}
```
Cursor shows `userMessage` to the human; `agentMessage` to the agent. ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))

Notes:
- There are also TypeScript helper types that model the response as `{ permission, userMessage?, agentMessage? }` (no `continue`), but real Cursor behavior appears to accept the `continue` field as well. ([github.com](https://github.com/johnlindquist/cursor-hooks))

### 2.3 beforeMCPExecution
**Payload** includes:
- `tool_name`
- `tool_input` (often a JSON string)
- `command` (the MCP server command)
- `hook_event_name: "beforeMCPExecution"` ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))

**Response**: same shape as beforeShellExecution (permission allow/deny/ask + optional messages). ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))

⚠️ Naming mismatch in some sources:
- Some type defs refer to `arguments` instead of `tool_input` ([github.com](https://github.com/johnlindquist/cursor-hooks))
- In practice, Cursor has been observed sending `tool_input` (string) ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))

So: handle **both**.

### 2.4 beforeReadFile
**Payload** includes:
- `file_path` (string)
- `content` (string)
- `hook_event_name: "beforeReadFile"` ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))

**Response** (at minimum):
- `permission: "allow"|"deny"` with optional messages ([github.com](https://github.com/johnlindquist/cursor-hooks))

### 2.5 afterFileEdit
**Payload** includes:
- `file_path`
- `edits: [{ old_string, new_string }, ... ]`
- `hook_event_name: "afterFileEdit"` ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))

**Response**: informational only (Cursor does not respect output here in current releases, per early deep dive). ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))

### 2.6 beforeSubmitPrompt
**Payload** includes:
- `prompt`
- `attachments` (often)
- ids + `hook_event_name: "beforeSubmitPrompt"` ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))

**Response**: nominally `{"continue": boolean}` per type defs, but in at least one early analysis Cursor did not respect output for this hook at the time. Treat as “best effort” gating (log/audit + optionally deny if Cursor respects it in your version). ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))

### 2.7 stop
**Payload** includes:
- `status`
- `hook_event_name: "stop"` ([github.com](https://github.com/johnlindquist/cursor-hooks))

**Response**: none.

---

## 3) Auto-Run modes vs hooks (Run Everything / Use Allowlist / Ask Every Time)

### 3.1 What Cursor itself says about Auto-Run safety
Cursor explicitly says:
- terminal commands require approval by default
- users can enable auto-run (“Run Everything”) at their own risk
- the allowlist is **best-effort** and **not a security control**; bypasses may exist
- “Run Everything” bypasses allowlists ([docs.cursor.com](https://docs.cursor.com/en/account/agent-security?utm_source=chatgpt.com))

### 3.2 Observed interaction: allowlist can override hook decisions
A recent forum report claims that when Auto-Run is set to “Use Allowlist”, **hook responses of `allow`/`ask` may be ignored** and the allowlist takes precedence; only `deny` reliably blocks. ([forum.cursor.com](https://forum.cursor.com/t/beforeshellexecution-hook-permissions-allow-ask-ignored-allow-list-takes-precedence/144244?utm_source=chatgpt.com))

### 3.3 Observed bug: `permission: "ask"` may not prompt
Another report: returning `permission: "ask"` can still execute immediately (no user prompt). ([forum.cursor.com](https://forum.cursor.com/t/hook-ask-output-not-stopping-agent/149002?utm_source=chatgpt.com))

### Practical implication for HARP gate design
If you need a **reliable** human-approval gate independent of Cursor Auto-Run settings:
- Prefer using **`permission: "deny"`** to block until you have explicit approval.
- Don’t rely on `ask` for safety.
- Consider “deny-then-user-reruns” flows or “deny with instructions” flows.

---

## 4) HARP gate script review (hooksGateScript.js)

### 4.1 High-level architecture
The script:
- reads JSON stdin
- infers an “event” (beforeShellExecution / beforeMCPExecution / beforeReadFile / unknown)
- blocks any attempt to access/modify protected hook files
- submits an approval artifact to `AIRLOCK_GATEWAY_URL`
- long-polls for decision
- outputs `{ continue, permission }` and exits 0 (allow) or 2 (deny)

### 4.2 Spec alignment — what’s OK
✅ Uses stdin JSON + stdout JSON + exit codes for allow/deny. fileciteturn1file6L5-L15

✅ Uses `continue` + `permission` fields consistent with observed Cursor hook response shape. fileciteturn1file4L20-L34 ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))

✅ Uses `permission: "deny"` for rejected/timed-out approvals — this is the most reliable gating strategy given current reports. fileciteturn1file4L24-L35 ([forum.cursor.com](https://forum.cursor.com/t/beforeshellexecution-hook-permissions-allow-ask-ignored-allow-list-takes-precedence/144244?utm_source=chatgpt.com))

### 4.3 Spec misalignments / bugs (must fix)

#### Bug A — Event inference is incorrect: Cursor **does** provide `hook_event_name`
Code comment says Cursor “does NOT send an event field” and tries to infer it. fileciteturn1file0L25-L35

But Cursor sends `hook_event_name` in payloads. ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))

**Fix**:
- set `payload.event = payload.hook_event_name` (or just use `hook_event_name` throughout)
- keep heuristic fallback only if `hook_event_name` is absent

#### Bug B — Wrong payload field names for file hooks
The script looks for `payload.path` and `payload.filePath`, or `payload.input.path`, etc. fileciteturn1file0L51-L56

Spec uses:
- `beforeReadFile.file_path`
- `afterFileEdit.file_path`
- plus `content` / `edits` ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))

**Fix**:
- treat the canonical file path as:
  - `payload.file_path` (for beforeReadFile / afterFileEdit)
  - optionally also support legacy / experimental names (`path`, `filePath`) as fallback

#### Bug C — `tool_input` is usually a **string**, but script treats it as an object
The gate normalizes:
- `payload.input = payload.tool_input` fileciteturn1file0L22-L24

…but later assumes `payload.input.path` exists, etc. fileciteturn1file0L51-L56

In observed payloads, `tool_input` is an escaped JSON string. ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))

**Fix**:
- if `typeof tool_input === "string"`, attempt `JSON.parse(tool_input)` to get an object
- keep raw string in a separate field (e.g. `tool_input_raw`) for logging

#### Bug D — Incorrect response field casing: uses `user_message` / `agent_message`
Cursor expects `userMessage` / `agentMessage` in stdout. ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))

Script outputs `user_message` and `agent_message` in multiple places. fileciteturn1file1L31-L38 fileciteturn1file4L26-L34

**Fix**: rename to camelCase everywhere.

#### Bug E — Mentions hook events that don’t exist in Cursor hooks (in this system)
`buildDescription` references `preToolUse` and uses `payload.input?.path` for read/edit. fileciteturn1file3L41-L53

Cursor Agent hooks in the current official config schema are these 6 only: `beforeShellExecution`, `beforeMCPExecution`, `afterFileEdit`, `beforeReadFile`, `beforeSubmitPrompt`, `stop`. ([unpkg.com](https://unpkg.com/cursor-hooks%40latest/schema/hooks.schema.json))

**Fix**:
- remove `preToolUse` from the logic unless you actually support another system
- map descriptions using the real payload fields (`command`, `tool_name`, `file_path`, etc.)

#### Bug F — “self-protection” path extraction misses most real cases
Self-protection tries to detect protected files via `filePath = payload.path || ...`. fileciteturn1file0L51-L56

But for file hooks the field is `file_path`. So protected-file access might slip through.

**Fix**:
- include `payload.file_path` in the candidate list
- also check `payload.command` for strings referencing `.cursor/hooks.json` etc.

---

## 5) Recommended spec-aligned gate design

### 5.1 Parse + normalize payload (single function)
Create a single normalizer that outputs a stable internal shape:

```ts
type NormalizedHook = {
  event: string;               // from hook_event_name
  workspaceRoots: string[];

  // shell
  command?: string;
  cwd?: string;

  // mcp
  toolName?: string;
  toolInput?: unknown;         // parsed object
  toolInputRaw?: string;       // original string
  mcpCommand?: string;         // the server command, if present

  // file
  filePath?: string;
  fileContent?: string;
  edits?: Array<{ old_string: string; new_string: string }>;

  // prompt
  prompt?: string;
  attachments?: unknown[];
};
```

Normalization rules:
- `event = payload.hook_event_name ?? heuristic(payload)`
- `workspaceRoots = payload.workspace_roots ?? []`
- shell: `command = payload.command`, `cwd = payload.cwd`
- mcp: `toolName = payload.tool_name ?? payload.toolName`
- mcp input:
  - `toolInputRaw = payload.tool_input ?? payload.arguments`
  - if `toolInputRaw` is string → `toolInput = JSON.parse(toolInputRaw)` (try/catch)
  - if already object → `toolInput = toolInputRaw`
- file hooks:
  - `filePath = payload.file_path ?? payload.path ?? payload.filePath`
  - `fileContent = payload.content`
  - `edits = payload.edits`

### 5.2 Decide which hooks should go through “approval”
Given the Auto-Run interaction issues, it’s safest to gate only **truly risky** actions and allow benign ones.

#### Strong candidates for approval
1) `beforeShellExecution` (terminal commands)
- Always gate, or gate based on policy (denylist/regex risk scoring)
- Return `permission: "deny"` until approved

2) `beforeMCPExecution` (third-party tools)
- Usually high risk (network / data exfil)
- Gate by tool name / server

3) `beforeReadFile` (data exfil)
- Gate reads of sensitive paths (`.env`, ssh keys, cloud creds, private keys, prod config)
- If not sensitive, allow

#### Not good candidates for approval (informational)
- `afterFileEdit` and `stop` are informational; don’t attempt to gate. ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))
- `beforeSubmitPrompt` may not consistently respect output; use for audit/telemetry and optionally block if your Cursor version honors it. ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))

### 5.3 Return the correct response shape per hook
Implement a helper:

```ts
function respondAllow(msgs?) {
  return { continue: true, permission: "allow", ...msgs };
}

function respondDeny(userMessage, agentMessage) {
  return { continue: false, permission: "deny", userMessage, agentMessage };
}
```

Key points:
- Use `userMessage` / `agentMessage` (camelCase)
- For reliability, prefer `deny` for “not yet approved” actions

### 5.4 Explicitly handle hook types
Do not route “unknown” events to approval — it can lock up the IDE.

Suggested behavior:
- If `hook_event_name` is missing/unknown:
  - log raw payload
  - allow (fail open) OR deny only if you strongly need “fail closed”

---

## 6) Concrete patch list for hooksGateScript.js

1) **Use `hook_event_name`**
- Replace event inference logic with:
  - `payload.event = payload.hook_event_name ?? payload.event ?? infer(...)`

2) **Fix file path extraction**
- include `payload.file_path` before `payload.path`

3) **Parse `tool_input`**
- if `payload.tool_input` is string, parse JSON

4) **Fix output casing**
- replace `user_message` → `userMessage`
- replace `agent_message` → `agentMessage`

5) **Remove/ignore non-Cursor events**
- drop `preToolUse` logic unless you truly support it

6) **Make protected-file detection spec-aware**
- check:
  - `payload.file_path`
  - `payload.command`
  - `payload.tool_input` (raw string)

7) **Decide fail-open vs fail-closed consistently**
Right now, the comment says “FAIL CLOSED throughout”, but then `AIRLOCK_GATEWAY_URL` / `AIRLOCK_ROUTING_TOKEN` missing → allow (exit 0). fileciteturn1file1L41-L52

Pick one:
- “fail open until paired” (good UX)
- “fail closed always” (strong policy)

Document it in-code.

---

## 7) Quick test matrix (what to verify manually)

### Hook payload parsing
- beforeShellExecution payload includes `hook_event_name`, `command`, `cwd`
- beforeMCPExecution payload includes `tool_name`, `tool_input` as **string**
- beforeReadFile includes `file_path`, `content`

### Auto-Run interaction
Test 3 Cursor settings:
- Ask Every Time
- Use Allowlist
- Run Everything

For each, run a shell command that the allowlist would permit and ensure:
- your gate can still block with `deny`
- if you try `ask`, verify whether Cursor prompts or not (known to be buggy per reports). ([forum.cursor.com](https://forum.cursor.com/t/hook-ask-output-not-stopping-agent/149002?utm_source=chatgpt.com))

---

## 8) References
- Cursor hooks config schema (unpkg): ([unpkg.com](https://unpkg.com/cursor-hooks%40latest/schema/hooks.schema.json))
- Hook types + response shapes (TS helpers): ([github.com](https://github.com/johnlindquist/cursor-hooks))
- Hook payload examples + stdout format: ([blog.gitbutler.com](https://blog.gitbutler.com/cursor-hooks-deep-dive))
- Cursor docs snippet on hook locations + working dir: ([cursor.com](https://cursor.com/docs/agent/hooks?utm_source=chatgpt.com))
- Auto-run safety notes + allowlist caveats: ([docs.cursor.com](https://docs.cursor.com/en/account/agent-security?utm_source=chatgpt.com))
- Reports about allowlist overriding hooks / ask misbehavior: ([forum.cursor.com](https://forum.cursor.com/t/beforeshellexecution-hook-permissions-allow-ask-ignored-allow-list-takes-precedence/144244?utm_source=chatgpt.com))



## IMPORTANT SECURITY NOTE

Missing `AIRLOCK_GATEWAY_URL` and `AIRLOCK_ROUTING_TOKEN` (or their modern equivalents `AIRLOCK_PIPE_NAME` and `AIRLOCK_LOCAL_SECRET`) MUST be treated as **fail open**. The enforcer must never block actions if it isn't configured.
