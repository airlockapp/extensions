"""Crypto helpers: base64url, SHA-256, HKDF, X25519, XChaCha20-Poly1305, Ed25519.

Mirrors Harp.Common/Crypto.cs + Harp.Common/NsecAead.cs from the C# implementation.
"""

from __future__ import annotations

import base64
import hashlib
import os
from typing import NamedTuple

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import nacl.bindings
import nacl.signing


# ──────────────── Base64url ────────────────


def to_b64url(data: bytes) -> str:
    """Encode bytes to a base64url string (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def from_b64url(s: str) -> bytes:
    """Decode a base64url string (with or without padding) to bytes."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


# ──────────────── Hashing ────────────────


def sha256_hex(s: str) -> str:
    """Return the lowercase hex SHA-256 digest of a UTF-8 string."""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ──────────────── HKDF-SHA256 ────────────────


def derive_key(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """Derive a symmetric key using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)


# ──────────────── X25519 Key Exchange ────────────────


class X25519Keypair(NamedTuple):
    public_key: bytes   # 32 bytes
    private_key: bytes  # 32 bytes


def create_x25519_keypair() -> X25519Keypair:
    """Generate an X25519 (Curve25519) keypair for key exchange."""
    pk, sk = nacl.bindings.crypto_box_keypair()
    return X25519Keypair(public_key=pk, private_key=sk)


def x25519_derive_shared(my_private_key: bytes, peer_public_key: bytes) -> bytes:
    """Compute X25519 shared secret (raw scalar multiplication)."""
    return nacl.bindings.crypto_scalarmult(my_private_key, peer_public_key)


# ──────────────── XChaCha20-Poly1305 AEAD ────────────────


class AeadResult(NamedTuple):
    nonce: bytes       # 24 bytes
    ciphertext: bytes
    tag: bytes         # 16 bytes


_XCHACHA_NONCE_BYTES = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  # 24
_XCHACHA_TAG_BYTES = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_ABYTES       # 16


def xchacha_encrypt(key32: bytes, plaintext: bytes, aad: bytes) -> AeadResult:
    """Encrypt with XChaCha20-Poly1305 (detached: ciphertext + tag separate)."""
    nonce = os.urandom(_XCHACHA_NONCE_BYTES)
    combined = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, aad, nonce, key32,
    )
    # combined = ciphertext || tag (last 16 bytes)
    ciphertext = combined[: -_XCHACHA_TAG_BYTES]
    tag = combined[-_XCHACHA_TAG_BYTES:]
    return AeadResult(nonce=nonce, ciphertext=ciphertext, tag=tag)


def xchacha_decrypt(
    key32: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes,
) -> bytes:
    """Decrypt with XChaCha20-Poly1305 (detached: recombine ciphertext + tag)."""
    combined = ciphertext + tag
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
        combined, aad, nonce, key32,
    )


# ──────────────── Ed25519 Signing ────────────────


class Ed25519Keypair(NamedTuple):
    public_key: bytes   # 32 bytes
    private_key: bytes  # 64 bytes (seed + pub)


def create_ed25519_keypair() -> Ed25519Keypair:
    """Generate an Ed25519 signing keypair."""
    signing_key = nacl.signing.SigningKey.generate()
    return Ed25519Keypair(
        public_key=bytes(signing_key.verify_key),
        private_key=bytes(signing_key._signing_key),
    )


def ed25519_sign(private_key: bytes, message: bytes) -> bytes:
    """Sign a message with Ed25519. Returns the 64-byte detached signature."""
    signing_key = nacl.signing.SigningKey(private_key[:32])  # seed is first 32 bytes
    signed = signing_key.sign(message)
    return signed.signature  # 64 bytes


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature. Returns True if valid, False otherwise."""
    verify_key = nacl.signing.VerifyKey(public_key)
    try:
        verify_key.verify(message, signature)
        return True
    except nacl.exceptions.BadSignatureError:
        return False


# ──────────────── Random Bytes ────────────────


def random_bytes(n: int) -> bytes:
    """Generate n cryptographically secure random bytes."""
    return os.urandom(n)
