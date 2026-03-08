package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	AESKeySize   = 32
	AESNonceSize = 12
	AESTagSize   = 16
)

// AESGCMEncrypt encrypts plaintext with AES-256-GCM. Key must be 32 bytes.
// Returns data, nonce, tag (all base64-encoded for gateway compatibility).
func AESGCMEncrypt(key []byte, plaintext []byte) (dataB64, nonceB64, tagB64 string, err error) {
	if len(key) != AESKeySize {
		return "", "", "", fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", "", err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	// GCM appends tag to ciphertext; split for gateway format (data, nonce, tag)
	tagLen := aead.Overhead()
	data := ciphertext[:len(ciphertext)-tagLen]
	tag := ciphertext[len(ciphertext)-tagLen:]
	return base64.StdEncoding.EncodeToString(data),
		base64.StdEncoding.EncodeToString(nonce),
		base64.StdEncoding.EncodeToString(tag),
		nil
}

// ArtifactHash computes SHA-256 hex of the canonical action string (matches extension).
func ArtifactHash(actionType, commandText string, nowMillis int64) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", actionType, commandText, nowMillis)))
	return fmt.Sprintf("%x", h)
}

// X25519Keypair holds a Curve25519 keypair for ECDH.
type X25519Keypair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// GenerateX25519Keypair creates a new X25519 keypair for pairing.
func GenerateX25519Keypair() (*X25519Keypair, error) {
	priv := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(priv); err != nil {
		return nil, err
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	return &X25519Keypair{PublicKey: pub, PrivateKey: priv}, nil
}

// DeriveSharedKey performs X25519 ECDH and derives 32-byte AES key with HKDF-SHA256.
// Info string must match mobile (HARP-E2E-AES256GCM).
func DeriveSharedKey(localPrivate, remotePublic []byte) ([]byte, error) {
	shared, err := curve25519.X25519(localPrivate, remotePublic)
	if err != nil {
		return nil, err
	}
	const info = "HARP-E2E-AES256GCM"
	r := hkdf.New(sha256.New, shared, nil, []byte(info))
	key := make([]byte, AESKeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// PublicKeyToBase64URL returns the raw 32-byte public key as base64url (mobile sends raw).
func PublicKeyToBase64URL(pub []byte) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}

// DecodeBase64URL decodes base64url to bytes (strict; requires valid padding for padded encoding).
func DecodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// base64url alphabet (RFC 4648); index 0-63 map to 6-bit value
const base64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// decodeBase64URLManual decodes unpadded base64url (e.g. 43 chars -> 32 bytes) without relying on std lib padding.
func decodeBase64URLManual(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	// Build reverse lookup: char -> 6-bit value
	var decodeMap [256]int8
	for i := range decodeMap {
		decodeMap[i] = -1
	}
	for i := 0; i < len(base64urlAlphabet); i++ {
		decodeMap[base64urlAlphabet[i]] = int8(i)
	}
	// Also accept standard base64 +/
	decodeMap['+'] = 62
	decodeMap['/'] = 63

	var bits uint
	var nbits int
	var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '=' {
			break
		}
		v := decodeMap[c]
		if v < 0 {
			continue // skip invalid chars
		}
		bits = (bits << 6) | uint(v)
		nbits += 6
		if nbits >= 8 {
			nbits -= 8
			out = append(out, byte((bits>>nbits)&0xff))
		}
	}
	return out, nil
}

// DecodeBase64URLFlexible decodes base64url or base64 to bytes, with or without padding.
// The mobile app sends X25519 public key as unpadded base64url (43 chars for 32 bytes).
// We try manual decode first (handles 43-char unpadded), then fall back to std lib with padding.
func DecodeBase64URLFlexible(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty base64 string")
	}
	// Strip any character not in the base64 alphabet (handles newlines/JSON artifacts)
	var buf []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '+' || c == '/' || c == '=' {
			buf = append(buf, c)
		}
	}
	if len(buf) == 0 {
		return nil, fmt.Errorf("no base64 characters in input")
	}
	clean := string(buf)

	// Mobile X25519 key: Dart sends 43 chars (unpadded) or 44 chars (43 + '='). Always decode
	// with manual decoder to avoid std lib "illegal base64 data at input byte 43" on some platforms.
	dataLen := len(buf)
	if dataLen == 44 && buf[43] == '=' {
		dataLen = 43 // strip trailing padding so we decode 43 data chars
	}
	if dataLen >= 43 {
		toDecode := clean
		if dataLen < len(buf) {
			toDecode = clean[:dataLen]
		}
		out, err := decodeBase64URLManual(toDecode)
		if err == nil && len(out) == 32 {
			return out, nil
		}
	}

	// Fallback: normalize and use std lib
	buf = bytes.ReplaceAll(buf, []byte("-"), []byte("+"))
	buf = bytes.ReplaceAll(buf, []byte("_"), []byte("/"))
	for len(buf)%4 != 0 {
		buf = append(buf, '=')
	}
	return base64.StdEncoding.DecodeString(string(buf))
}

// Ed25519Verify verifies an Ed25519 signature. Canonical message format: "artifactHash|decision|nonce".
func Ed25519Verify(publicKey ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}

// DecodeBase64Signature decodes base64 or base64url signature to bytes.
func DecodeBase64Signature(s string) ([]byte, error) {
	s = base64Normalize(s)
	return base64.StdEncoding.DecodeString(s)
}

// DecodeBase64PublicKey decodes base64 (or base64url) Ed25519 public key.
// Mobile may send raw 32-byte key; we accept both.
func DecodeBase64PublicKey(s string) (ed25519.PublicKey, error) {
	s = base64Normalize(s)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) == 32 {
		return ed25519.PublicKey(b), nil
	}
	// DER/SPKI: skip header to get 32-byte key (0x302a300506032b6570032100 + 32 bytes)
	if len(b) >= 44 && b[0] == 0x30 {
		return ed25519.PublicKey(b[len(b)-32:]), nil
	}
	return nil, fmt.Errorf("unexpected public key length: %d", len(b))
}

func base64Normalize(s string) string {
	b := []byte(s)
	b = bytes.ReplaceAll(b, []byte("-"), []byte("+"))
	b = bytes.ReplaceAll(b, []byte("_"), []byte("/"))
	for len(b)%4 != 0 {
		b = append(b, '=')
	}
	return string(b)
}