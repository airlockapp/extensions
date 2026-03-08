# Windsurf Hook Reject Issue — AI-Friendly Analysis and Fix Plan

## Problem Summary

The hook script is clearly receiving a **reject** decision from the gateway, and the log shows the process is exiting with code `2`. However, Windsurf still runs the command.

From the observed behavior, this means one of these is happening:

1. The hook process is **not actually the one Windsurf is waiting on**.
2. The wrapper script returns success even though the Node hook returns `2`.
3. The hook exits too late or in a way that Windsurf does not treat as a blocking pre-hook failure.
4. The hook configuration or wrapper path is correct enough to run, but not correct enough to propagate the blocking exit code back to Windsurf.

The screenshot strongly suggests the most likely root cause is **exit code propagation through the Windows `.cmd` wrapper**, not the gateway decision logic itself.

---

## High-Confidence Root Cause

Your logs show all of the following:

- hook started
- event detected (`pre_run_command`)
- decision submitted
- gateway returned `reject`
- script printed `BLOCKED`
- script printed `Airlock REJECTED`
- script says `*** Process exiting with code 2 ***`

That means the internal decision logic is probably working.

If Windsurf still executes the command, then the most probable issue is:

> **The command that Windsurf launches is a `.cmd` wrapper, and that wrapper is not returning the Node process exit code back to Windsurf correctly.**

On Windows, this happens very often when a batch file uses `node script.js` but does not explicitly forward `%ERRORLEVEL%` using `exit /b %ERRORLEVEL%`.

---

## Primary Fixes

## Fix 1 — Make the `.cmd` wrapper propagate the exit code

### What to check
Open your wrapper file, likely something like:

- `airlock-gate.cmd`
- `hooks-gate.cmd`
- or whatever file Windsurf is configured to execute

### Bad pattern

```bat
@echo off
node hooksGateScript.js
```

This is not reliable enough.

### Correct pattern

```bat
@echo off
setlocal
node "%~dp0hooksGateScript.js" %*
set "EXITCODE=%ERRORLEVEL%"
exit /b %EXITCODE%
```

### Better version if TypeScript output or a custom Node path is used

```bat
@echo off
setlocal
node "D:\path\to\hooksGateScript.js" %*
set "EXITCODE=%ERRORLEVEL%"
exit /b %EXITCODE%
```

### Why this matters
Windsurf blocks only if the launched hook process returns exit code `2`.
If the `.cmd` script always ends as `0`, then Windsurf will think the hook succeeded and continue with the command.

---

## Fix 2 — In Node, use a hard `process.exit(2)` for reject/fail-closed paths

### Why
If the hook is supposed to block execution, do not rely only on:

```js
process.exitCode = 2;
```

That merely sets the future exit code. It does **not** terminate immediately.
If there are still active handles, pending timers, pipe sockets, or async cleanup, the process may continue in a way Windsurf does not interpret correctly.

### Replace with this style

```js
function deny(reason, agentMessage) {
    log(`BLOCKED: ${reason}`);

    const msg = agentMessage ||
        "STOP. This action was blocked by Airlock. " +
        "Do NOT retry automatically. Inform the user and wait for explicit instruction.";

    process.stderr.write(`⛔ Airlock REJECTED: ${reason}\n${msg}\n`, () => {
        process.exit(2);
    });
}
```

### Also update fatal fail-closed paths

```js
main().catch(err => {
    log(`FATAL: ${err?.message || err} — blocking (fail closed)`);
    process.exit(2);
});
```

### AI instruction
Search for all places where a reject or fail-closed outcome should block execution and replace any use of:

```js
process.exitCode = 2;
```

with a real terminating path using:

```js
process.exit(2)
```

or a `stderr.write(..., () => process.exit(2))` callback.

---

## Fix 3 — Ensure the wrapper uses `call` if another batch file is involved

If your `.cmd` calls another `.cmd` or `.bat`, use `call`.

### Wrong

```bat
other-wrapper.cmd
exit /b %ERRORLEVEL%
```

### Correct

```bat
call other-wrapper.cmd
exit /b %ERRORLEVEL%
```

Without `call`, batch control flow may not return the way you expect.

---

## Fix 4 — Remove ambiguity by making the hook executable be the final blocking process

If possible, avoid multi-layer wrappers.

### Preferred order

Windsurf -> one `.cmd` wrapper -> `node hooksGateScript.js`

### Avoid

Windsurf -> `.cmd` -> another `.cmd` -> PowerShell -> Node -> TS launcher -> actual logic

The more layers you add, the more likely exit code `2` gets lost.

---

## Secondary Hardening Fixes

## Fix 5 — End or destroy pipe/socket resources deterministically

If `pipeRequest()` uses sockets/timers, make sure the reject path does not leave resources hanging.

### Recommended pattern

- on success: `socket.end()`
- on timeout: `socket.destroy()`
- on error: `socket.destroy()`
- clear timeouts after response

### Example

```js
function pipeRequest(payload, timeoutMs) {
    return new Promise((resolve, reject) => {
        const socket = net.createConnection(pipeName);
        let settled = false;

        const timer = setTimeout(() => {
            if (settled) return;
            settled = true;
            socket.destroy();
            reject(new Error("Pipe request timed out"));
        }, timeoutMs);

        socket.on("connect", () => {
            socket.write(JSON.stringify(payload));
            socket.end();
        });

        socket.on("data", chunk => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            resolve(chunk.toString("utf8"));
        });

        socket.on("error", err => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            socket.destroy();
            reject(err);
        });

        socket.on("close", () => {
            clearTimeout(timer);
        });
    });
}
```

This is not the most likely root cause, but it reduces unpredictable behavior.

---

## Fix 6 — Unify reject handling into one single block-and-exit function

The hook should have exactly one authoritative block path.

### Recommended helper

```js
function blockAndExit(reason, agentMessage) {
    log(`BLOCKED: ${reason}`);

    const message = agentMessage ||
        "STOP. This action was blocked by Airlock. Do not retry automatically.";

    process.stderr.write(
        `⛔ Airlock REJECTED: ${reason}\n${message}\n`,
        () => process.exit(2)
    );
}
```

Then all reject cases should call only this helper.

---

## Fix 7 — Fail closed on malformed responses

If the gateway response is malformed, unknown, or partially missing, block.

### Example logic

```js
if (!decision || typeof decision !== "string") {
    blockAndExit("Malformed approval decision from gateway");
}

if (decision === "reject") {
    blockAndExit("Action rejected by Airlock mobile approver.");
}

if (decision === "approve") {
    process.exit(0);
}

blockAndExit(`Unknown gateway decision: ${decision}`);
```

---

## Most Important Change for the AI to Make First

If the AI is going to fix only one thing first, it should do this:

1. Find the `.cmd` file that Windsurf executes.
2. Make sure it ends with:

```bat
@echo off
setlocal
node "%~dp0hooksGateScript.js" %*
set "EXITCODE=%ERRORLEVEL%"
exit /b %EXITCODE%
```

3. In `hooksGateScript.js`, replace reject/fatal `process.exitCode = 2` flows with direct `process.exit(2)`.

This combination has the highest chance of fixing the issue.

---

## AI Task Instructions

Give the following instructions to the AI that will edit the code:

### Task
Fix the Windsurf pre-hook rejection flow so that a reject decision from the gateway truly blocks command execution.

### Required changes

1. Inspect the Windows wrapper script that Windsurf launches.
2. Ensure the wrapper returns the Node process exit code using `exit /b %ERRORLEVEL%`.
3. If the wrapper calls another batch file, use `call`.
4. In `hooksGateScript.js`, replace non-terminating reject/fail-closed patterns based on `process.exitCode = 2` with a deterministic blocking exit using `process.exit(2)`.
5. Ensure all reject, timeout, malformed-response, and fatal-error paths fail closed with exit code `2`.
6. Keep allow paths returning `0`.
7. Avoid leaving live sockets/timers that could delay process shutdown.

### Acceptance criteria

When the gateway returns `reject`:

- Windsurf must show the hook failure
- Windsurf must **not** run the tool/command
- the wrapper process must exit with code `2`
- no success path should overwrite that exit code

---

## Suggested Verification Steps

### Test 1 — Direct wrapper test in terminal
Run the exact wrapper command manually and then inspect the exit code.

#### cmd.exe

```bat
D:\path\to\airlock-gate.cmd
echo %ERRORLEVEL%
```

Expected when rejected:

```bat
2
```

### Test 2 — Temporary forced reject mode
Temporarily hardcode the hook to always reject:

```js
blockAndExit("Forced reject test");
```

If Windsurf still runs the command, the issue is definitely wrapper or Windsurf config propagation, not gateway logic.

### Test 3 — Temporary trivial wrapper
Create a minimal wrapper:

```bat
@echo off
exit /b 2
```

Point Windsurf to that file as the pre-hook.

If Windsurf still runs the command, then the issue is very likely in hook registration/configuration rather than your gateway logic.

If Windsurf blocks correctly with this trivial wrapper, then your original wrapper/script chain is the problem.

---

## Final Recommendation

The fastest and most likely successful fix is:

- fix the `.cmd` exit code propagation first
- then make Node reject paths terminate explicitly with `process.exit(2)`

The screenshot already shows the reject decision is being produced. So this does **not** look like an approval logic bug. It looks like a **process-exit propagation bug**.

