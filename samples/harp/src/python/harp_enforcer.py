#!/usr/bin/env python3
"""HE Verifier — verifies Decision signature, binds to Artifact, enforces expiry & replay.

Mirrors Harp.Enforcer/Program.cs from the C# implementation.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

from harp.crypto_helpers import from_b64url, ed25519_verify
from harp.canonical_json import jcs_canonicalize
from harp.nonce_journal import NonceJournalStore

MA_KEYS_FILE = r"C:\tmp\harp\ma-keys.json"
ARTIFACT_WIRE_FILE = r"C:\tmp\harp\artifact-wire.json"
DECISION_FILE = r"C:\tmp\harp\decision.json"
NONCE_JOURNAL_FILE = r"C:\tmp\harp\nonce-journal.ndjson"


def fail(msg: str) -> None:
    """Print rejection message and exit."""
    print("❌ REJECT: " + msg)
    sys.exit(1)


# ──────────────── Main ────────────────


def main() -> None:
    if not os.path.exists(MA_KEYS_FILE):
        fail(f"Missing {MA_KEYS_FILE}.")
    if not os.path.exists(ARTIFACT_WIRE_FILE):
        fail(f"Missing {ARTIFACT_WIRE_FILE}.")
    if not os.path.exists(DECISION_FILE):
        fail(f"Missing {DECISION_FILE}.")

    with open(MA_KEYS_FILE, encoding="utf-8") as f:
        keys = json.load(f)

    ma_ed_pub_b64url = keys["maEd25519PubRawB64Url"]
    expected_signer_key_id = keys["signerKeyId"]

    with open(ARTIFACT_WIRE_FILE, encoding="utf-8") as f:
        artifact_wire = json.load(f)

    with open(DECISION_FILE, encoding="utf-8") as f:
        decision = json.load(f)

    # Basic binding
    if decision["requestId"] != artifact_wire["requestId"]:
        fail("Decision.requestId != Artifact.requestId")

    if decision["repoRef"] != artifact_wire["repoRef"]:
        fail("Decision.repoRef != Artifact.repoRef")

    if decision["artifactHashAlg"] != artifact_wire["artifactHashAlg"]:
        fail("Decision.artifactHashAlg != Artifact.artifactHashAlg")

    if decision["artifactHash"].lower() != artifact_wire["artifactHash"].lower():
        fail("Decision.artifactHash != Artifact.artifactHash")

    # Enforce expiry
    now = datetime.now(timezone.utc)

    artifact_expires = datetime.fromisoformat(artifact_wire["expiresAt"])
    if now > artifact_expires:
        fail(f"Artifact expired at {artifact_wire['expiresAt']}")

    decision_expires = datetime.fromisoformat(decision["expiresAt"])
    if now > decision_expires:
        fail(f"Decision expired at {decision['expiresAt']}")

    # Signer checks
    if decision["sigAlg"] != "Ed25519":
        fail(f"Unsupported sigAlg: {decision['sigAlg']}")

    if decision["signerKeyId"] != expected_signer_key_id:
        fail(f"Unknown signerKeyId: {decision['signerKeyId']}")

    # Verify signature over DecisionSignable (JCS)
    signable = {
        "requestId": decision["requestId"],
        "artifactHashAlg": decision["artifactHashAlg"],
        "artifactHash": decision["artifactHash"],
        "repoRef": decision["repoRef"],
        "decision": decision["decision"],
        "scope": decision["scope"],
        "expiresAt": decision["expiresAt"],
        "nonce": decision["nonce"],
        "sigAlg": decision["sigAlg"],
        "signerKeyId": decision["signerKeyId"],
    }

    signable_canon = jcs_canonicalize(signable).encode("utf-8")
    ma_ed_pub_raw = from_b64url(ma_ed_pub_b64url)
    sig_bytes = from_b64url(decision["signature"])

    if not ed25519_verify(ma_ed_pub_raw, signable_canon, sig_bytes):
        fail("Invalid signature")

    # Anti-replay journal for scope=once
    nonce_ttl_seconds = 24 * 60 * 60  # 24 hours
    journal = NonceJournalStore(NONCE_JOURNAL_FILE)
    replay_key = f"{decision['nonce']}:{decision['artifactHash']}"

    if decision["scope"] == "once":
        if journal.seen(replay_key, now, nonce_ttl_seconds):
            fail("Replay detected (nonce already seen)")

        journal.record(replay_key, now)
        journal.compact_if_needed(now, nonce_ttl_seconds, max_bytes=2 * 1024 * 1024)

    elif decision["scope"] in ("timebox", "session"):
        # Demo policy: timebox/session rely on expiresAt
        pass
    else:
        fail(f"Unsupported scope: {decision['scope']}")

    print("✅ Decision verified and bound to artifactHash.")
    print(f"Decision: {decision['decision']}  Scope: {decision['scope']}")
    print(f"ArtifactType: {artifact_wire['artifactType']}")
    print(f"RepoRef: {artifact_wire['repoRef']}")
    print(f"ArtifactHash: {artifact_wire['artifactHash']}")

    if decision["decision"] == "allow":
        print("🟢 ENFORCER RESULT: ALLOW")
        sys.exit(0)

    if decision["decision"] == "deny":
        print("🔴 ENFORCER RESULT: DENY")
        sys.exit(2)

    fail(f"Unknown decision value: {decision['decision']}")


if __name__ == "__main__":
    main()
