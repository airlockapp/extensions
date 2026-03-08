// Package harpcrypto provides cryptographic primitives for the HARP protocol.
package harpcrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// ──────────────── Base64url ────────────────

// ToB64URL encodes bytes to a base64url string (no padding).
func ToB64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// FromB64URL decodes a base64url string to bytes.
func FromB64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// ──────────────── Hashing ────────────────

// SHA256Hex returns the lowercase hex SHA-256 digest of a string.
func SHA256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

// ──────────────── HKDF-SHA256 ────────────────

// DeriveKey derives a key using HKDF-SHA256.
func DeriveKey(ikm, salt, info []byte, length int) ([]byte, error) {
	reader := hkdf.New(sha256.New, ikm, salt, info)
	key := make([]byte, length)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return key, nil
}

// ──────────────── X25519 Key Exchange ────────────────

// X25519Keypair holds a Curve25519 keypair for key exchange.
type X25519Keypair struct {
	PublicKey  []byte // 32 bytes
	PrivateKey []byte // 32 bytes
}

// CreateX25519Keypair generates a new X25519 keypair.
func CreateX25519Keypair() (*X25519Keypair, error) {
	priv := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(priv); err != nil {
		return nil, fmt.Errorf("x25519 keygen: %w", err)
	}

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("x25519 basepoint mul: %w", err)
	}

	return &X25519Keypair{PublicKey: pub, PrivateKey: priv}, nil
}

// X25519DeriveShared computes the X25519 shared secret.
func X25519DeriveShared(myPrivate, peerPublic []byte) ([]byte, error) {
	shared, err := curve25519.X25519(myPrivate, peerPublic)
	if err != nil {
		return nil, fmt.Errorf("x25519 derive: %w", err)
	}
	return shared, nil
}

// ──────────────── XChaCha20-Poly1305 AEAD ────────────────

// AEADResult holds the output of AEAD encryption in detached mode.
type AEADResult struct {
	Nonce      []byte // 24 bytes
	Ciphertext []byte
	Tag        []byte // 16 bytes
}

// XChaChaEncrypt encrypts with XChaCha20-Poly1305 in detached mode.
func XChaChaEncrypt(key32, plaintext, aad []byte) (*AEADResult, error) {
	aead, err := chacha20poly1305.NewX(key32)
	if err != nil {
		return nil, fmt.Errorf("xchacha new: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX) // 24 bytes
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("xchacha nonce: %w", err)
	}

	// Seal appends ciphertext+tag to dst
	sealed := aead.Seal(nil, nonce, plaintext, aad)

	// Detach: split ciphertext and tag (last 16 bytes)
	tagSize := aead.Overhead() // 16
	ct := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

	return &AEADResult{Nonce: nonce, Ciphertext: ct, Tag: tag}, nil
}

// XChaChaDecrypt decrypts with XChaCha20-Poly1305 in detached mode.
func XChaChaDecrypt(key32, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key32)
	if err != nil {
		return nil, fmt.Errorf("xchacha new: %w", err)
	}

	// Recombine ciphertext + tag
	combined := append(ciphertext, tag...)

	plaintext, err := aead.Open(nil, nonce, combined, aad)
	if err != nil {
		return nil, fmt.Errorf("xchacha decrypt: %w", err)
	}

	return plaintext, nil
}

// ──────────────── Ed25519 Signing ────────────────

// Ed25519Keypair holds an Ed25519 signing keypair.
type Ed25519Keypair struct {
	PublicKey  ed25519.PublicKey  // 32 bytes
	PrivateKey ed25519.PrivateKey // 64 bytes
}

// CreateEd25519Keypair generates a new Ed25519 signing keypair.
func CreateEd25519Keypair() (*Ed25519Keypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 keygen: %w", err)
	}
	return &Ed25519Keypair{PublicKey: pub, PrivateKey: priv}, nil
}

// Ed25519Sign signs a message with an Ed25519 private key.
func Ed25519Sign(privateKey ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}

// Ed25519Verify verifies an Ed25519 signature.
func Ed25519Verify(publicKey ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}

// ──────────────── Random Bytes ────────────────

// RandomBytes generates n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
