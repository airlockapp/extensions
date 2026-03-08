// Harp.Executor/Program.cs
// Creates an Artifact, computes artifactHash (JCS), encrypts ONLY payload using NSec XChaCha20-Poly1305,
// writes artifact-wire.json.
//
// NuGet needed in this project:
// - NSec.Cryptography
// - jsoncanonicalizer (if you implement JCS there; here we do our own JCS via JsonCanonicalizer directly)

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Harp.Common;
using Org.Webpki.JsonCanonicalizer;
using NSec.Cryptography;

namespace Harp.Executor
{
    internal static class Program
    {
        private const string MaKeysFile = "C:\\tmp\\harp\\ma-keys.json";
        private const string ArtifactWireFile = "C:\\tmp\\harp\\artifact-wire.json";

        public static void Main(string[] args)
        {
            if (!File.Exists(MaKeysFile))
            {
                Console.WriteLine($"Missing {MaKeysFile}. Run Harp.Approver once to generate MA keys.");
                Environment.Exit(1);
            }

            var maKeys = JsonDocument.Parse(File.ReadAllText(MaKeysFile)).RootElement;
            var maKxPubB64Url = maKeys.GetProperty("maKxPubRawB64Url").GetString()!;
            var maSignPubB64Url = maKeys.GetProperty("maEd25519PubRawB64Url").GetString()!;
            var signerKeyId = maKeys.GetProperty("signerKeyId").GetString()!;

            Console.WriteLine("Loaded MA public keys:");
            Console.WriteLine($"  MA X25519 pub: {Preview(maKxPubB64Url)}");
            Console.WriteLine($"  MA Ed25519 pub: {Preview(maSignPubB64Url)}");
            Console.WriteLine($"  signerKeyId: {signerKeyId}");

            var now = DateTimeOffset.UtcNow;

            // Payload (reviewable content)
            var payload = new
            {
                command = "echo \"hello harp\"",
                workingDirectory = "/tmp",
                timeoutSeconds = 10
            };

            // Build "artifact-without artifactHash" (logical plaintext) for hashing
            var requestId = Guid.NewGuid().ToString("N");
            var artifactWithoutHash = new
            {
                requestId,
                sessionId = (string?)null,
                artifactType = "command.review",
                repoRef = "repo:opaque:demo",
                baseRevision = (string?)null,
                createdAt = now,
                expiresAt = now.AddMinutes(5),
                payload,
                artifactHashAlg = "SHA-256",
                // artifactHash omitted
                metadata = (object?)null,
                extensions = (object?)null
            };

            var artifactHashHex = Sha256Hex(JcsCanonicalize(artifactWithoutHash));

            // Build AAD (bind enc to immutable header+hash)
            var aadObj = new
            {
                requestId,
                sessionId = (string?)null,
                artifactType = "command.review",
                repoRef = "repo:opaque:demo",
                baseRevision = (string?)null,
                createdAt = now,
                expiresAt = now.AddMinutes(5),
                artifactHashAlg = "SHA-256",
                artifactHash = artifactHashHex
            };
            var aad = Encoding.UTF8.GetBytes(JcsCanonicalize(aadObj));

            // ---- Key agreement (X25519) + HKDF-SHA256 -> 32-byte AEAD key ----
            // Load MA X25519 public key
            var maKxPubRaw = FromB64Url(maKxPubB64Url);
            var kxAlg = KeyAgreementAlgorithm.X25519;
            var maKxPublic = PublicKey.Import(kxAlg, maKxPubRaw, KeyBlobFormat.RawPublicKey);

            // Generate ephemeral HE X25519 keypair (exportable)
            using var heKxKey = new Key(kxAlg, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            var heKxPubRaw = heKxKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);

            // Shared secret
            var sharedSecret = kxAlg.Agree(heKxKey, maKxPublic);

            // HKDF inputs
            var salt = RandomNumberGenerator.GetBytes(16);
            var infoStr = "HARP-XCHACHA-PAYLOAD-V1";
            var info = Encoding.UTF8.GetBytes(infoStr);

            var hkdf = KeyDerivationAlgorithm.HkdfSha256;
            var keyMaterial = hkdf.DeriveBytes(sharedSecret, salt, info, 32); // 32-byte symmetric key

            // ---- AEAD XChaCha20-Poly1305 ----
            var aeadAlg = AeadAlgorithm.XChaCha20Poly1305;
            using var aeadKey = Key.Import(aeadAlg, keyMaterial, KeyBlobFormat.RawSymmetricKey);

            var nonce = RandomNumberGenerator.GetBytes(aeadAlg.NonceSize);
            var payloadJson = JsonSerializer.Serialize(payload, JsonOpts());
            var payloadBytes = Encoding.UTF8.GetBytes(payloadJson);

            // Encrypt returns ciphertext||tag
            var combined = aeadAlg.Encrypt(aeadKey, nonce, aad, payloadBytes);
            SplitCiphertextAndTag(aeadAlg, combined, out var ciphertext, out var tag);

            // Build ArtifactWire (payload is encrypted)
            var artifactWire = new ArtifactWire
            {
                requestId = requestId,
                sessionId = null,
                artifactType = "command.review",
                repoRef = "repo:opaque:demo",
                baseRevision = null,
                createdAt = now,
                expiresAt = now.AddMinutes(5),
                artifactHashAlg = "SHA-256",
                artifactHash = artifactHashHex,
                metadata = null,
                extensions = null,
                enc = new EncBlob
                {
                    kdf = "X25519+HKDF-SHA256",
                    encAlg = "XChaCha20-Poly1305",
                    maKxPub = maKxPubB64Url,
                    heKxPub = ToB64Url(heKxPubRaw),
                    salt = ToB64Url(salt),
                    info = infoStr,
                    nonce = ToB64Url(nonce),
                    ciphertext = ToB64Url(ciphertext),
                    tag = ToB64Url(tag)
                }
            };

            File.WriteAllText(ArtifactWireFile, JsonSerializer.Serialize(artifactWire, new JsonSerializerOptions
            {
                WriteIndented = true,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            }));

            Console.WriteLine();
            Console.WriteLine("✅ Wrote artifact-wire.json");
            Console.WriteLine($"artifactHash: {artifactHashHex}");
        }

        // ---------------- Helpers ----------------

        private static JsonSerializerOptions JsonOpts() => new JsonSerializerOptions
        {
            WriteIndented = false,
            PropertyNamingPolicy = null,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };

        private static string JcsCanonicalize(object obj)
        {
            var json = JsonSerializer.Serialize(obj, JsonOpts());
            var jcs = new JsonCanonicalizer(json);
            return jcs.GetEncodedString();
        }

        private static string Sha256Hex(string s)
        {
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(s));
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        private static void SplitCiphertextAndTag(AeadAlgorithm alg, byte[] combined, out byte[] ciphertext, out byte[] tag)
        {
            var tagSize = alg.TagSize;
            if (combined.Length < tagSize) throw new CryptographicException("Combined ciphertext shorter than tag.");

            var ctLen = combined.Length - tagSize;
            ciphertext = new byte[ctLen];
            tag = new byte[tagSize];

            Buffer.BlockCopy(combined, 0, ciphertext, 0, ctLen);
            Buffer.BlockCopy(combined, ctLen, tag, 0, tagSize);

            CryptographicOperations.ZeroMemory(combined);
        }

        private static string Preview(string s) => s.Length <= 18 ? s : s.Substring(0, 18) + "...";

        private static string ToB64Url(byte[] bytes)
            => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        private static byte[] FromB64Url(string s)
        {
            s = s.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
            }
            return Convert.FromBase64String(s);
        }
    }
}