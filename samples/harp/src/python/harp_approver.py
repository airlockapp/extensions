#!/usr/bin/env python3
"""Mobile Approver — generates MA keys (first run), decrypts artifact, signs decision.

Mirrors Harp.Approver/Program.cs from the C# implementation.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone, timedelta

from harp.crypto_helpers import (
    to_b64url, from_b64url, sha256_hex, derive_key,
    create_x25519_keypair, x25519_derive_shared,
    create_ed25519_keypair, ed25519_sign, ed25519_verify,
    xchacha_decrypt, random_bytes,
)
from harp.canonical_json import jcs_canonicalize

MA_KEYS_FILE = r"C:\tmp\harp\ma-keys.json"
ARTIFACT_WIRE_FILE = r"C:\tmp\harp\artifact-wire.json"
DECISION_FILE = r"C:\tmp\harp\decision.json"


def preview(s: str) -> str:
    return s[:18] + "..." if len(s) > 18 else s


# ──────────────── Key Bootstrap ────────────────


def ensure_keys_exist() -> None:
    """Generate MA keys if they don't exist yet."""
    if os.path.exists(MA_KEYS_FILE):
        return

    print("Generating MA keys...")

    # X25519 keypair for payload decryption
    kx_kp = create_x25519_keypair()

    # Ed25519 keypair for decision signing
    sign_kp = create_ed25519_keypair()

    keys = {
        "maKxPubRawB64Url": to_b64url(kx_kp.public_key),
        "maKxPrivRawB64Url": to_b64url(kx_kp.private_key),
        "maEd25519PubRawB64Url": to_b64url(sign_kp.public_key),
        "maEd25519PrivRawB64Url": to_b64url(sign_kp.private_key),
        "signerKeyId": "ma-key-1",
    }

    os.makedirs(r"C:\tmp\harp", exist_ok=True)
    with open(MA_KEYS_FILE, "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=2)

    print(f"✅ Wrote {MA_KEYS_FILE}")


# ──────────────── Main ────────────────


def main() -> None:
    ensure_keys_exist()

    with open(MA_KEYS_FILE, encoding="utf-8") as f:
        keys = json.load(f)

    ma_kx_priv_raw = from_b64url(keys["maKxPrivRawB64Url"])
    ma_sign_priv_raw = from_b64url(keys["maEd25519PrivRawB64Url"])
    ma_sign_pub_raw = from_b64url(keys["maEd25519PubRawB64Url"])
    signer_key_id = keys["signerKeyId"]

    if not os.path.exists(ARTIFACT_WIRE_FILE):
        print(f"Missing {ARTIFACT_WIRE_FILE}. Run harp_executor.py first.")
        sys.exit(0)  # First run was just key generation

    with open(ARTIFACT_WIRE_FILE, encoding="utf-8") as f:
        artifact_wire = json.load(f)

    # Basic enc sanity
    if artifact_wire["enc"]["encAlg"] != "XChaCha20-Poly1305":
        print(f"❌ Unsupported encAlg: {artifact_wire['enc']['encAlg']}")
        sys.exit(1)

    if artifact_wire["enc"]["kdf"] != "X25519+HKDF-SHA256":
        print(f"❌ Unsupported kdf: {artifact_wire['enc']['kdf']}")
        sys.exit(1)

    # Rebuild AAD (must match HE)
    aad_obj = {
        "requestId": artifact_wire["requestId"],
        "artifactType": artifact_wire["artifactType"],
        "repoRef": artifact_wire["repoRef"],
        "createdAt": artifact_wire["createdAt"],
        "expiresAt": artifact_wire["expiresAt"],
        "artifactHashAlg": artifact_wire["artifactHashAlg"],
        "artifactHash": artifact_wire["artifactHash"],
    }
    aad = jcs_canonicalize(aad_obj).encode("utf-8")

    # ──── Key agreement + HKDF ────

    he_kx_pub_raw = from_b64url(artifact_wire["enc"]["heKxPub"])
    shared_secret = x25519_derive_shared(ma_kx_priv_raw, he_kx_pub_raw)

    salt = from_b64url(artifact_wire["enc"]["salt"])
    info = (artifact_wire["enc"].get("info") or "HARP-XCHACHA-PAYLOAD-V1").encode("utf-8")
    key_material = derive_key(shared_secret, salt, info, 32)

    # ──── AEAD decrypt ────

    nonce = from_b64url(artifact_wire["enc"]["nonce"])
    ciphertext = from_b64url(artifact_wire["enc"]["ciphertext"])
    tag = from_b64url(artifact_wire["enc"]["tag"])

    try:
        plaintext = xchacha_decrypt(key_material, nonce, ciphertext, tag, aad)
    except Exception as e:
        print(f"❌ Decryption/auth failed: {e}")
        sys.exit(1)

    payload_json = plaintext.decode("utf-8")
    payload_obj = json.loads(payload_json)

    # ──── Verify artifactHash ────

    artifact_without_hash = {
        "requestId": artifact_wire["requestId"],
        "artifactType": artifact_wire["artifactType"],
        "repoRef": artifact_wire["repoRef"],
        "createdAt": artifact_wire["createdAt"],
        "expiresAt": artifact_wire["expiresAt"],
        "payload": payload_obj,
        "artifactHashAlg": artifact_wire["artifactHashAlg"],
    }

    recomputed = sha256_hex(jcs_canonicalize(artifact_without_hash))
    if recomputed.lower() != artifact_wire["artifactHash"].lower():
        print("❌ Hash mismatch. Refuse.")
        print(f"Expected: {artifact_wire['artifactHash']}")
        print(f"Actual:   {recomputed}")
        sys.exit(1)

    print("✅ Payload decrypted and artifactHash verified.")
    print()
    print("----- REVIEW PAYLOAD -----")
    print(payload_json)
    print("--------------------------")
    print()

    answer = input("Approve? (y/n): ").strip().lower()
    decision_value = "allow" if answer == "y" else "deny"

    decision_expires = datetime.now(timezone.utc) + timedelta(minutes=10)
    decision_nonce = to_b64url(random_bytes(16))

    # Build DecisionSignable and sign
    signable = {
        "requestId": artifact_wire["requestId"],
        "artifactHashAlg": artifact_wire["artifactHashAlg"],
        "artifactHash": artifact_wire["artifactHash"],
        "repoRef": artifact_wire["repoRef"],
        "decision": decision_value,
        "scope": "once",
        "expiresAt": decision_expires.isoformat(),
        "nonce": decision_nonce,
        "sigAlg": "Ed25519",
        "signerKeyId": signer_key_id,
    }

    signable_canon = jcs_canonicalize(signable).encode("utf-8")
    signature = ed25519_sign(ma_sign_priv_raw, signable_canon)

    # Optional self-verify
    if not ed25519_verify(ma_sign_pub_raw, signable_canon, signature):
        print("❌ Signature self-verify failed.")
        sys.exit(1)

    decision = {
        **signable,
        "signature": to_b64url(signature),
    }

    with open(DECISION_FILE, "w", encoding="utf-8") as f:
        json.dump(decision, f, indent=2)

    print(f"✅ Wrote {DECISION_FILE} ({decision['decision']})")


if __name__ == "__main__":
    main()
