#!/usr/bin/env python3
"""HE Proposer — builds & encrypts artifacts.

Mirrors Harp.Executor/Program.cs from the C# implementation.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone, timedelta

from harp.crypto_helpers import (
    to_b64url, from_b64url, sha256_hex, derive_key,
    create_x25519_keypair, x25519_derive_shared,
    xchacha_encrypt, random_bytes,
)
from harp.canonical_json import jcs_canonicalize

MA_KEYS_FILE = r"C:\tmp\harp\ma-keys.json"
ARTIFACT_WIRE_FILE = r"C:\tmp\harp\artifact-wire.json"


def preview(s: str) -> str:
    return s[:18] + "..." if len(s) > 18 else s


def main() -> None:
    if not os.path.exists(MA_KEYS_FILE):
        print(f"Missing {MA_KEYS_FILE}. Run harp_approver.py once to generate MA keys.")
        sys.exit(1)

    with open(MA_KEYS_FILE, encoding="utf-8") as f:
        ma_keys = json.load(f)

    ma_kx_pub_b64url = ma_keys["maKxPubRawB64Url"]
    ma_sign_pub_b64url = ma_keys["maEd25519PubRawB64Url"]
    signer_key_id = ma_keys["signerKeyId"]

    print("Loaded MA public keys:")
    print(f"  MA X25519 pub: {preview(ma_kx_pub_b64url)}")
    print(f"  MA Ed25519 pub: {preview(ma_sign_pub_b64url)}")
    print(f"  signerKeyId: {signer_key_id}")

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=5)

    # Payload (reviewable content)
    payload = {
        "command": 'echo "hello harp"',
        "workingDirectory": "/tmp",
        "timeoutSeconds": 10,
    }

    # Build "artifact-without artifactHash" for hashing
    request_id = uuid.uuid4().hex
    artifact_without_hash = {
        "requestId": request_id,
        "artifactType": "command.review",
        "repoRef": "repo:opaque:demo",
        "createdAt": now.isoformat(),
        "expiresAt": expires_at.isoformat(),
        "payload": payload,
        "artifactHashAlg": "SHA-256",
    }

    artifact_hash_hex = sha256_hex(jcs_canonicalize(artifact_without_hash))

    # Build AAD (bind encryption to immutable header + hash)
    aad_obj = {
        "requestId": request_id,
        "artifactType": "command.review",
        "repoRef": "repo:opaque:demo",
        "createdAt": now.isoformat(),
        "expiresAt": expires_at.isoformat(),
        "artifactHashAlg": "SHA-256",
        "artifactHash": artifact_hash_hex,
    }
    aad = jcs_canonicalize(aad_obj).encode("utf-8")

    # ──── Key agreement (X25519) + HKDF-SHA256 → 32-byte AEAD key ────

    ma_kx_pub_raw = from_b64url(ma_kx_pub_b64url)

    # Generate ephemeral HE X25519 keypair
    he_kx = create_x25519_keypair()

    # Shared secret
    shared_secret = x25519_derive_shared(he_kx.private_key, ma_kx_pub_raw)

    # HKDF inputs
    salt = random_bytes(16)
    info_str = "HARP-XCHACHA-PAYLOAD-V1"
    info = info_str.encode("utf-8")
    key_material = derive_key(shared_secret, salt, info, 32)

    # ──── AEAD XChaCha20-Poly1305 ────

    payload_json = json.dumps(payload, separators=(",", ":"))
    payload_bytes = payload_json.encode("utf-8")
    enc_result = xchacha_encrypt(key_material, payload_bytes, aad)

    # Build ArtifactWire (payload is encrypted)
    artifact_wire = {
        "requestId": request_id,
        "artifactType": "command.review",
        "repoRef": "repo:opaque:demo",
        "createdAt": now.isoformat(),
        "expiresAt": expires_at.isoformat(),
        "artifactHashAlg": "SHA-256",
        "artifactHash": artifact_hash_hex,
        "enc": {
            "kdf": "X25519+HKDF-SHA256",
            "encAlg": "XChaCha20-Poly1305",
            "maKxPub": ma_kx_pub_b64url,
            "heKxPub": to_b64url(he_kx.public_key),
            "salt": to_b64url(salt),
            "info": info_str,
            "nonce": to_b64url(enc_result.nonce),
            "ciphertext": to_b64url(enc_result.ciphertext),
            "tag": to_b64url(enc_result.tag),
        },
    }

    os.makedirs(r"C:\tmp\harp", exist_ok=True)
    with open(ARTIFACT_WIRE_FILE, "w", encoding="utf-8") as f:
        json.dump(artifact_wire, f, indent=2)

    print()
    print("✅ Wrote artifact-wire.json")
    print(f"artifactHash: {artifact_hash_hex}")


if __name__ == "__main__":
    main()
