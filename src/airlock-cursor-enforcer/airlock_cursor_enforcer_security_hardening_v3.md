
# Airlock Cursor Enforcer Security Hardening — v3 (Standards‑Grade Implementation Plan)

This document is the **standards‑grade implementation specification** for securing the
`airlock-cursor-enforcer` extension.

Repository target:

    airlockapp/airlock/src/extensions/airlock-cursor-enforcer

This document is written for **AI coding agents and human reviewers** and contains:

• full architecture
• security invariants
• pseudocode
• runtime lifecycle
• bootstrap implementation
• multi‑root workspace model
• pipe server lifecycle
• failure policy matrix
• migration plan
• acceptance tests

The goal is to make implementation **unambiguous and safe**.

---

# 1. Security Invariants

These invariants MUST hold at all times.

### INV‑1
No secrets may appear in:

```
.cursor/
environment variables
bootstrap scripts
git repositories
logs
```

### INV‑2
All secrets MUST be stored only in:

```
VS Code SecretStorage
```

### INV‑3
Bootstrap scripts must be **safe to publish in public repos**.

### INV‑4
Approval decisions are evaluated only inside the **trusted extension runtime**.

### INV‑5
Workspace folders are the **security isolation unit**.

### INV‑6
Each workspace folder has its own:

• pipe/socket  
• encryption keys  
• routing token  
• pairing state  
• failure policy  

### INV‑7
Fail‑mode must default to:

```
failClosed
```

### INV‑8
Explicit rejection can **never** be overridden by failOpen.

---

# 2. High Level Architecture

Final architecture:

```
Cursor Hook
     │
     ▼
.cursor/airlock-bootstrap
     │
     ▼
Named Pipe / Unix Socket
     │
     ▼
Extension Runtime (Trusted Boundary)
     │
     ▼
Gateway
     │
     ▼
Approver
     │
     ▼
Allow / Deny
```

Bootstrap = **transport only**  
Runtime = **security boundary**

---

# 3. Multi‑Root Workspace Model

VS Code allows multiple folders per workspace.

Airlock treats **each folder as a separate security domain**.

Example:

```
Workspace Window
 ├─ repo-A
 ├─ repo-B
 └─ repo-C
```

Each folder runs independent Airlock context.

---

# 4. Workspace Context Registry

Extension must maintain:

```
Map<string, WorkspaceContext>
```

Key = workspaceFolderUri

WorkspaceContext structure:

```
WorkspaceContext
{
    workspaceHash
    pipeName
    localSecret
    routingToken
    encryptionKey
    pairingState
    failMode
    runtimeStatus
}
```

---

# 5. Workspace Hash Algorithm

Workspace hash is deterministic.

Pseudocode:

```
function computeWorkspaceHash(path):

    normalized = normalize(path)

    if windows:
        normalized = normalized.lower()

    resolved = resolveSymlinks(normalized)

    digest = sha256(resolved)

    return digest[0:16]
```

Example:

```
a81f92d04e6f45c2
```

---

# 6. Pipe Naming

One pipe per workspace.

### Windows

```
\\.\pipe\airlock-ws-<hash>
```

### Unix

```
/tmp/airlock-ws-<hash>.sock
```

Properties:

• deterministic  
• stable across sessions  
• collision safe  

---

# 7. Pipe Server Lifecycle

Runtime starts pipe server during extension activation.

Pseudocode:

```
for folder in workspaceFolders:

    hash = computeWorkspaceHash(folder)

    context = loadWorkspaceContext(hash)

    pipe = createPipe(hash)

    startPipeServer(pipe, context)
```

On extension shutdown:

```
close pipe
cleanup socket file
```

---

# 8. Workspace Resolution Algorithm

Hooks must determine the correct workspace.

Resolution order:

1️⃣ file path match  
2️⃣ working directory match  
3️⃣ explicit metadata  
4️⃣ primary workspace fallback  

Primary workspace = first folder in workspace list.

If ambiguous:

```
failClosed → deny
failOpen → allow
```

---

# 9. Workspace Local Secret

Each workspace gets persistent secret.

Creation:

```
getOrCreateWorkspaceLocalSecret(workspaceHash)
```

Properties:

• stored in SecretStorage  
• persistent across sessions  
• used for IPC authentication  

---

# 10. Bootstrap Script Specification

Generated files:

```
.cursor/airlock-bootstrap.cmd
.cursor/airlock-bootstrap.sh
```

Bootstrap MUST:

1. read stdin
2. resolve workspace
3. connect pipe
4. send request
5. receive decision
6. print response
7. exit code

Bootstrap MUST NOT:

• access gateway
• read secrets
• log files
• reference extension install path

---

# 11. Example Bootstrap (POSIX)

Example minimal design:

```
#!/bin/sh

payload=$(cat)

pipe="/tmp/airlock-ws-<hash>.sock"

response=$(printf "%s" "$payload" | nc -U "$pipe")

echo "$response"

exit $?
```

Actual implementation may use node or netcat replacement.

---

# 12. Pipe Protocol

Replace pseudo‑HTTP with JSON.

Request:

```
{
  "kind": "hook_request",
  "protocolVersion": 1,
  "workspaceHash": "...",
  "payload": {...}
}
```

Response:

```
{
  "permission": "allow"
}
```

or

```
{
  "permission": "deny",
  "message": "Blocked by Airlock"
}
```

---

# 13. Runtime Request Flow

Runtime pseudocode:

```
handleHook(request):

    ctx = resolveWorkspaceContext(request.workspaceHash)

    if ctx.invalid:
        return deny

    if runtimeUnavailable:
        return applyFailMode()

    decision = submitToGateway()

    if decision == approve:
        return allow

    return deny
```

---

# 14. Fail Mode Policy

Configuration:

```
airlock.failMode
```

Options:

```
failClosed
failOpen
```

Default:

```
failClosed
```

---

# 15. Failure Matrix

| Condition | failClosed | failOpen |
|----------|-----------|---------|
Runtime unavailable | Deny | Allow |
Gateway unreachable | Deny | Allow |
User not signed in | Deny | Allow |
Workspace not paired | Deny | Allow |
Quota exceeded | Deny | Allow |

Always deny:

• explicit rejection  
• approval timeout  
• signature failure  
• IPC auth failure  
• workspace mismatch  

---

# 16. Logging Rules

All logs go to:

```
VS Code OutputChannel
```

Remove legacy:

```
.cursor/airlock-hooks.log
```

Never log:

• routing tokens  
• encryption keys  
• artifacts  

---

# 17. Git Safety

If `.cursor` is tracked in git:

Display warning.

Bootstrap remains safe to commit.

Secrets never written there.

---

# 18. Migration Strategy

During activation:

Detect legacy artifacts:

```
.cursor/airlock-gate.cmd
.cursor/airlock-gate.sh
.cursor/airlock-hooks.log
```

Then:

```
delete legacy files
install bootstrap
preserve secure state
```

---

# 19. Acceptance Tests

### Security

• no secrets in `.cursor`  
• bootstrap contains no tokens  
• logs contain no secrets  

### Runtime

• restart preserves workspace secret  
• approval rejection blocks command  

### Fail Mode

• runtime down + failClosed → deny  
• runtime down + failOpen → allow  

### Multi‑root

• separate pipes per folder  
• pairing independent  

---

# 20. Implementation Order

1️⃣ workspace hash system  
2️⃣ workspace context registry  
3️⃣ pipe server lifecycle  
4️⃣ secret storage model  
5️⃣ bootstrap scripts  
6️⃣ runtime request handling  
7️⃣ fail mode implementation  
8️⃣ legacy migration cleanup  
9️⃣ security test suite  

---

# 21. Final Rule

`.cursor` must always remain:

```
zero‑secret
```

All secure state belongs exclusively to:

```
VS Code SecretStorage
```

This ensures Airlock repositories remain safe even when public.
