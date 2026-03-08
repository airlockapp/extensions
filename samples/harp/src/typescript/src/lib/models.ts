/**
 * Data models for the HARP protocol.
 * Mirrors Harp.Common model classes from the C# implementation.
 */

/** Encrypted blob containing all information needed to decrypt the artifact payload. */
export interface EncBlob {
    readonly kdf: string;          // "X25519+HKDF-SHA256"
    readonly encAlg: string;       // "XChaCha20-Poly1305"
    readonly maKxPub: string;      // base64url
    readonly heKxPub: string;      // base64url
    readonly salt: string;         // base64url (16 bytes)
    readonly info: string;         // "HARP-XCHACHA-PAYLOAD-V1"
    readonly nonce: string;        // base64url (24 bytes)
    readonly ciphertext: string;   // base64url
    readonly tag: string;          // base64url (16 bytes)
}

/** Artifact as transmitted over the wire (encrypted payload). */
export interface ArtifactWire {
    readonly requestId: string;
    readonly sessionId?: string;
    readonly artifactType: string;        // e.g. "command.review"
    readonly repoRef: string;             // opaque
    readonly baseRevision?: string;
    readonly createdAt: string;           // ISO 8601
    readonly expiresAt: string;           // ISO 8601
    readonly artifactHashAlg: string;     // "SHA-256"
    readonly artifactHash: string;        // 64 lowercase hex chars
    readonly metadata?: Record<string, unknown>;
    readonly extensions?: Record<string, unknown>;
    readonly enc: EncBlob;
}

/** Plaintext artifact (before encryption, used for hashing). */
export interface ArtifactPlain {
    readonly requestId: string;
    readonly sessionId?: string;
    readonly artifactType: string;
    readonly repoRef: string;
    readonly baseRevision?: string;
    readonly createdAt: string;
    readonly expiresAt: string;
    readonly payload: unknown;
    readonly artifactHashAlg: string;
    readonly artifactHash?: string;
    readonly metadata?: Record<string, unknown>;
    readonly extensions?: Record<string, unknown>;
}

/** Decision token fields that are signed (everything except signature). */
export interface DecisionSignable {
    readonly requestId: string;
    readonly artifactHashAlg: string;
    readonly artifactHash: string;
    readonly repoRef: string;
    readonly decision: "allow" | "deny";
    readonly scope: "once" | "timebox" | "session";
    readonly expiresAt: string;
    readonly nonce: string;
    readonly sigAlg: string;      // "Ed25519"
    readonly signerKeyId: string;
}

/** Complete decision token including signature. */
export interface Decision extends DecisionSignable {
    readonly signature: string;   // base64url
}

/** MA key material stored in ma-keys.json. */
export interface MaKeys {
    readonly maKxPubRawB64Url: string;
    readonly maKxPrivRawB64Url: string;
    readonly maEd25519PubRawB64Url: string;
    readonly maEd25519PrivRawB64Url: string;
    readonly signerKeyId: string;
}
