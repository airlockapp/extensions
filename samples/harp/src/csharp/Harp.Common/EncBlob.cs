namespace Harp.Common
{
    public sealed class EncBlob
    {
        public required string kdf { get; set; }          // "ECDH-P256+HKDF-SHA256"
        public required string encAlg { get; set; }       // "AES-256-GCM"
        public required string nonce { get; set; }        // base64url (12 bytes)
        public required string ciphertext { get; set; }   // base64url
        public required string tag { get; set; }          // base64url (16 bytes)
        public required string maKxPub { get; set; } // base64url SubjectPublicKeyInfo
        public required string heKxPub { get; set; } // base64url SubjectPublicKeyInfo
        public required string salt { get; set; }
        public required string info { get; set; }
    }
}
