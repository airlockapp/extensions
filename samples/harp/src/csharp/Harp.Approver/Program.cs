// Harp.Approver/Program.cs
// Generates MA keys if missing (X25519 for decrypt + Ed25519 for signing),
// reads artifact-wire.json, decrypts payload using NSec XChaCha20-Poly1305,
// verifies artifactHash (JCS), prompts allow/deny, signs Decision, writes decision.json.
//
// NuGet needed in this project:
// - NSec.Cryptography
// - jsoncanonicalizer

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Harp.Common;
using Org.Webpki.JsonCanonicalizer;
using NSec.Cryptography;

namespace Harp.Approver
{
    internal static class Program
    {
        private const string MaKeysFile = "C:\\tmp\\harp\\ma-keys.json";
        private const string ArtifactWireFile = "C:\\tmp\\harp\\artifact-wire.json";
        private const string DecisionFile = "C:\\tmp\\harp\\decision.json";

        public static void Main(string[] args)
        {
            EnsureKeysExist();

            var keys = JsonDocument.Parse(File.ReadAllText(MaKeysFile)).RootElement;
            var maKxPrivB64Url = keys.GetProperty("maKxPrivRawB64Url").GetString()!;
            var maKxPubB64Url = keys.GetProperty("maKxPubRawB64Url").GetString()!;
            var maSignPrivB64Url = keys.GetProperty("maEd25519PrivRawB64Url").GetString()!;
            var maSignPubB64Url = keys.GetProperty("maEd25519PubRawB64Url").GetString()!;
            var signerKeyId = keys.GetProperty("signerKeyId").GetString()!;

            if (!File.Exists(ArtifactWireFile))
            {
                Console.WriteLine($"Missing {ArtifactWireFile}. Run Harp.Executor first.");
                Environment.Exit(1);
            }

            var artifactWire = JsonSerializer.Deserialize<ArtifactWire>(
                File.ReadAllText(ArtifactWireFile),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!
                ?? throw new InvalidOperationException("Failed to parse artifact-wire.json");

            // Basic enc sanity
            if (!string.Equals(artifactWire.enc.encAlg, "XChaCha20-Poly1305", StringComparison.Ordinal))
            {
                Console.WriteLine($"❌ Unsupported encAlg: {artifactWire.enc.encAlg}");
                Environment.Exit(1);
            }
            if (!string.Equals(artifactWire.enc.kdf, "X25519+HKDF-SHA256", StringComparison.Ordinal))
            {
                Console.WriteLine($"❌ Unsupported kdf: {artifactWire.enc.kdf}");
                Environment.Exit(1);
            }

            // Rebuild AAD (must match HE)
            var aadObj = new
            {
                artifactWire.requestId,
                artifactWire.sessionId,
                artifactWire.artifactType,
                artifactWire.repoRef,
                artifactWire.baseRevision,
                artifactWire.createdAt,
                artifactWire.expiresAt,
                artifactWire.artifactHashAlg,
                artifactWire.artifactHash
            };
            var aad = Encoding.UTF8.GetBytes(JcsCanonicalize(aadObj));

            // ---- Key agreement + HKDF ----
            var kxAlg = KeyAgreementAlgorithm.X25519;

            // MA private key
            using var maKxKey = Key.Import(kxAlg, FromB64Url(maKxPrivB64Url), KeyBlobFormat.RawPrivateKey);

            // HE public key from artifact
            var heKxPubRaw = FromB64Url(artifactWire.enc.heKxPub);
            var heKxPublic = PublicKey.Import(kxAlg, heKxPubRaw, KeyBlobFormat.RawPublicKey);

            var sharedSecret = kxAlg.Agree(maKxKey, heKxPublic);

            var salt = FromB64Url(artifactWire.enc.salt);
            var info = Encoding.UTF8.GetBytes(artifactWire.enc.info ?? "HARP-XCHACHA-PAYLOAD-V1");

            var hkdf = KeyDerivationAlgorithm.HkdfSha256;
            var keyMaterial = hkdf.DeriveBytes(sharedSecret, salt, info, 32);

            // ---- AEAD decrypt (ciphertext||tag) ----
            var aeadAlg = AeadAlgorithm.XChaCha20Poly1305;
            using var aeadKey = Key.Import(aeadAlg, keyMaterial, KeyBlobFormat.RawSymmetricKey);

            var nonce = FromB64Url(artifactWire.enc.nonce);
            var ciphertext = FromB64Url(artifactWire.enc.ciphertext);
            var tag = FromB64Url(artifactWire.enc.tag);

            if (nonce.Length != aeadAlg.NonceSize)
            {
                Console.WriteLine($"❌ Invalid nonce size: {nonce.Length} (expected {aeadAlg.NonceSize})");
                Environment.Exit(1);
            }
            if (tag.Length != aeadAlg.TagSize)
            {
                Console.WriteLine($"❌ Invalid tag size: {tag.Length} (expected {aeadAlg.TagSize})");
                Environment.Exit(1);
            }

            var combined = new byte[ciphertext.Length + tag.Length];
            Buffer.BlockCopy(ciphertext, 0, combined, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, combined, ciphertext.Length, tag.Length);

            var plaintext = aeadAlg.Decrypt(aeadKey, nonce, aad, combined);
            CryptographicOperations.ZeroMemory(combined);

            if (plaintext is null)
            {
                Console.WriteLine("❌ Decryption/auth failed (tampered or wrong key/AAD).");
                Environment.Exit(1);
            }

            var payloadJson = Encoding.UTF8.GetString(plaintext);
            using var payloadDoc = JsonDocument.Parse(payloadJson);
            var payloadObj = payloadDoc.RootElement.Clone();

            // ---- Verify artifactHash by reconstructing plaintext artifact without artifactHash ----
            var artifactWithoutHash = new
            {
                artifactWire.requestId,
                artifactWire.sessionId,
                artifactWire.artifactType,
                artifactWire.repoRef,
                artifactWire.baseRevision,
                artifactWire.createdAt,
                artifactWire.expiresAt,
                payload = payloadObj,
                artifactWire.artifactHashAlg,
                // artifactHash omitted
                artifactWire.metadata,
                artifactWire.extensions
            };

            var recomputed = Sha256Hex(JcsCanonicalize(artifactWithoutHash));
            if (!string.Equals(recomputed, artifactWire.artifactHash, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("❌ Hash mismatch. Refuse.");
                Console.WriteLine($"Expected: {artifactWire.artifactHash}");
                Console.WriteLine($"Actual:   {recomputed}");
                Environment.Exit(1);
            }

            Console.WriteLine("✅ Payload decrypted and artifactHash verified.");
            Console.WriteLine();
            Console.WriteLine("----- REVIEW PAYLOAD -----");
            Console.WriteLine(payloadJson);
            Console.WriteLine("--------------------------");
            Console.WriteLine();

            Console.Write("Approve? (y/n): ");
            var answer = (Console.ReadLine() ?? "").Trim().ToLowerInvariant();
            var decisionValue = answer == "y" ? "allow" : "deny";

            var decisionExpires = DateTimeOffset.UtcNow.AddMinutes(10);
            var decisionNonce = ToB64Url(RandomNumberGenerator.GetBytes(16));

            // Build DecisionSignable and sign
            var signable = new DecisionSignable
            {
                requestId = artifactWire.requestId,
                artifactHashAlg = artifactWire.artifactHashAlg,
                artifactHash = artifactWire.artifactHash,
                repoRef = artifactWire.repoRef,
                decision = decisionValue,
                scope = "once",
                expiresAt = decisionExpires,
                nonce = decisionNonce,
                sigAlg = "Ed25519",
                signerKeyId = signerKeyId,
                policyHints = null
            };

            var signableCanon = JcsCanonicalize(signable);

            var sigAlg = SignatureAlgorithm.Ed25519;
            using var signKey = Key.Import(sigAlg, FromB64Url(maSignPrivB64Url), KeyBlobFormat.RawPrivateKey);

            var signature = sigAlg.Sign(signKey, Encoding.UTF8.GetBytes(signableCanon));

            // Optional self-verify
            var pub = PublicKey.Import(sigAlg, FromB64Url(maSignPubB64Url), KeyBlobFormat.RawPublicKey);
            if (!sigAlg.Verify(pub, Encoding.UTF8.GetBytes(signableCanon), signature))
            {
                Console.WriteLine("❌ Signature self-verify failed.");
                Environment.Exit(1);
            }

            var decision = new Decision
            {
                requestId = signable.requestId,
                artifactHashAlg = signable.artifactHashAlg,
                artifactHash = signable.artifactHash,
                repoRef = signable.repoRef,
                decision = signable.decision,
                scope = signable.scope,
                expiresAt = signable.expiresAt,
                nonce = signable.nonce,
                sigAlg = signable.sigAlg,
                signerKeyId = signable.signerKeyId,
                signature = ToB64Url(signature)
            };

            File.WriteAllText(DecisionFile, JsonSerializer.Serialize(decision, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"✅ Wrote {DecisionFile} ({decision.decision})");
        }

        // ---------------- Key bootstrap ----------------

        private static void EnsureKeysExist()
        {
            if (File.Exists(MaKeysFile))
                return;

            Console.WriteLine("Generating MA keys...");

            // X25519 keypair for decrypt
            var kxAlg = KeyAgreementAlgorithm.X25519;
            using var maKxKey = new Key(kxAlg, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            var maKxPub = maKxKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
            var maKxPriv = maKxKey.Export(KeyBlobFormat.RawPrivateKey);

            // Ed25519 signing keypair
            var sigAlg = SignatureAlgorithm.Ed25519;
            using var maSignKey = new Key(sigAlg, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            var maSignPub = maSignKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
            var maSignPriv = maSignKey.Export(KeyBlobFormat.RawPrivateKey);

            var keysObj = new
            {
                maKxPubRawB64Url = ToB64Url(maKxPub),
                maKxPrivRawB64Url = ToB64Url(maKxPriv),
                maEd25519PubRawB64Url = ToB64Url(maSignPub),
                maEd25519PrivRawB64Url = ToB64Url(maSignPriv),
                signerKeyId = "ma-key-1"
            };

            File.WriteAllText(MaKeysFile, JsonSerializer.Serialize(keysObj, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"✅ Wrote {MaKeysFile}");
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