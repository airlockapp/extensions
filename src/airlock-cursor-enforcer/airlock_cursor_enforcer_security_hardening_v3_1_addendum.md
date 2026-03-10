
# Airlock Cursor Enforcer Security Hardening — v3.1 Addendum
IPC Authentication, Pipe Security, Collision Handling, and Bootstrap Timeouts

This document is an addendum to the **Airlock Cursor Enforcer Security Hardening v3 specification**.
It fills the remaining security gaps identified during final review.

This addendum is intended to be **appended logically to the v3 spec**, but is provided as a
separate document for clarity and review.

---

# 1. IPC Authentication Specification

Named pipe / Unix socket communication must be authenticated to prevent
**local process injection attacks**.

Each workspace must have a **workspaceLocalSecret** stored in:

    VS Code SecretStorage

This secret must **never appear** in:

- `.cursor`
- environment variables
- bootstrap scripts
- logs
- git repositories

The secret is used exclusively for **IPC authentication between bootstrap and runtime**.

---

## 1.1 Request Authentication

Every request sent from bootstrap to the runtime must include authentication metadata.

Example request:

{
  "kind": "hook_request",
  "protocolVersion": 1,
  "workspaceHash": "a81f92d04e6f45c2",
  "auth": {
    "type": "workspace-secret",
    "secret": "<workspaceLocalSecret>"
  },
  "payload": {}
}

---

## 1.2 Runtime Verification

Runtime must verify the secret before processing the request.

Pseudocode:

    if request.auth.type != "workspace-secret":
        deny

    if request.auth.secret != storedWorkspaceSecret:
        deny

Invalid authentication must always result in:

    permission = deny

Fail-mode policy **must not override authentication failures**.

---

# 2. Socket / Pipe Security Requirements

Named pipe or Unix socket access must be restricted to the **current user only**.

This prevents other local users from injecting requests.

---

## 2.1 Unix Socket Permissions

After socket creation, permissions must be restricted to owner only.

Required:

    chmod 0600 <socket>

This ensures:

- only the current user can connect
- no group or world access exists

---

## 2.2 Windows Named Pipe ACL

On Windows, the named pipe must be created with **current-user-only ACL**.

Pipe security must restrict access to:

    current Windows user SID

Other users on the same machine must not be able to connect.

---

# 3. Pipe / Socket Collision Handling

A socket or pipe with the expected name may already exist when the extension starts.

Possible reasons:

- extension previously crashed
- stale socket file
- runtime already running
- another process accidentally created the same name

The runtime must handle this safely.

---

## 3.1 Collision Resolution Algorithm

Pseudocode:

    if socket_exists:

        attempt_connection()

        if connection_successful:
            reuse_existing_runtime()

        else:
            delete_socket()
            create_new_socket()

This ensures:

- stale sockets are cleaned up
- active runtimes are reused
- startup failures are avoided

---

# 4. Bootstrap Timeout Policy

Bootstrap must use deterministic timeout behavior when communicating with the runtime.

---

## 4.1 Connection Timeout

Bootstrap must attempt to connect to the pipe/socket with a short timeout.

Recommended:

    connection timeout = 300 milliseconds

If connection fails:

    runtimeUnavailable = true

---

## 4.2 Request Timeout

After connection succeeds, runtime may need time to contact the gateway and wait for approval.

Recommended:

    request timeout = 10 seconds

If the timeout expires, runtime is considered unavailable.

---

## 4.3 Fail Mode Behavior

If runtime is unavailable, bootstrap must apply fail-mode policy.

failClosed:

    deny command execution

failOpen:

    allow command execution

Explicit deny decisions must always override failOpen.

---

# 5. Protocol Version Validation

Runtime must validate protocol version compatibility.

If:

    request.protocolVersion != supportedProtocolVersion

then:

    deny request

This prevents incompatible bootstrap/runtime implementations from executing commands.

---

# 6. Payload Size Limits

To prevent abuse or memory exhaustion, hook requests must enforce a maximum payload size.

Recommended:

    maximum payload size = 1 MB

If exceeded:

    deny request

---

# 7. Final Security Requirement

With this addendum applied, the Airlock Cursor Enforcer architecture guarantees:

- zero secret leakage into `.cursor`
- authenticated local IPC
- user-only pipe access
- deterministic startup behavior
- deterministic timeout behavior
- safe multi-root workspace isolation

All secure state remains stored exclusively inside:

    VS Code SecretStorage
