// Harp.Enforcer/Program.cs
// Verifies Decision (Ed25519) and binds it to Artifact (requestId/repoRef/artifactHash), enforces expiry,
// and prevents replay via append-only nonce journal + compaction.
//
// NuGet needed in this project:
// - NSec.Cryptography
// - jsoncanonicalizer

using System.Text;
using System.Text.Json;
using Harp.Common;
using Org.Webpki.JsonCanonicalizer;
using NSec.Cryptography;

namespace Harp.Enforcer
{
    internal static class Program
    {
        private const string MaKeysFile = "C:\\tmp\\harp\\ma-keys.json";
        private const string ArtifactWireFile = "C:\\tmp\\harp\\artifact-wire.json";
        private const string DecisionFile = "C:\\tmp\\harp\\decision.json";
        private const string NonceJournalFile = "C:\\tmp\\harp\\nonce-journal.ndjson";

        public static void Main(string[] args)
        {
            if (!File.Exists(MaKeysFile)) Fail($"Missing {MaKeysFile}.");
            if (!File.Exists(ArtifactWireFile)) Fail($"Missing {ArtifactWireFile}.");
            if (!File.Exists(DecisionFile)) Fail($"Missing {DecisionFile}.");

            var keys = JsonDocument.Parse(File.ReadAllText(MaKeysFile)).RootElement;
            var maEdPubB64Url = keys.GetProperty("maEd25519PubRawB64Url").GetString()!;
            var expectedSignerKeyId = keys.GetProperty("signerKeyId").GetString()!;

            var artifactWire = JsonSerializer.Deserialize<ArtifactWire>(
                File.ReadAllText(ArtifactWireFile),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!
                ?? throw new InvalidOperationException("Failed to parse artifact-wire.json");

            var decision = JsonSerializer.Deserialize<Decision>(
                File.ReadAllText(DecisionFile),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!
                ?? throw new InvalidOperationException("Failed to parse decision.json");

            // Basic binding
            if (!string.Equals(decision.requestId, artifactWire.requestId, StringComparison.Ordinal))
                Fail("Decision.requestId != Artifact.requestId");

            if (!string.Equals(decision.repoRef, artifactWire.repoRef, StringComparison.Ordinal))
                Fail("Decision.repoRef != Artifact.repoRef");

            if (!string.Equals(decision.artifactHashAlg, artifactWire.artifactHashAlg, StringComparison.Ordinal))
                Fail("Decision.artifactHashAlg != Artifact.artifactHashAlg");

            if (!string.Equals(decision.artifactHash, artifactWire.artifactHash, StringComparison.OrdinalIgnoreCase))
                Fail("Decision.artifactHash != Artifact.artifactHash");

            // Enforce expiry
            var now = DateTimeOffset.UtcNow;
            if (now > artifactWire.expiresAt) Fail($"Artifact expired at {artifactWire.expiresAt:O}");
            if (now > decision.expiresAt) Fail($"Decision expired at {decision.expiresAt:O}");

            // Signer checks
            if (!string.Equals(decision.sigAlg, "Ed25519", StringComparison.Ordinal))
                Fail($"Unsupported sigAlg: {decision.sigAlg}");

            if (!string.Equals(decision.signerKeyId, expectedSignerKeyId, StringComparison.Ordinal))
                Fail($"Unknown signerKeyId: {decision.signerKeyId}");

            // Verify signature over DecisionSignable (JCS)
            var signable = new DecisionSignable
            {
                requestId = decision.requestId,
                artifactHashAlg = decision.artifactHashAlg,
                artifactHash = decision.artifactHash,
                repoRef = decision.repoRef,
                decision = decision.decision,
                scope = decision.scope,
                expiresAt = decision.expiresAt,
                nonce = decision.nonce,
                sigAlg = decision.sigAlg,
                signerKeyId = decision.signerKeyId,
                policyHints = null // must match what Approver signed
            };

            var signableCanon = JcsCanonicalize(signable);

            var sigAlg = SignatureAlgorithm.Ed25519;
            var pub = PublicKey.Import(sigAlg, FromB64Url(maEdPubB64Url), KeyBlobFormat.RawPublicKey);
            var sigBytes = FromB64Url(decision.signature);

            if (!sigAlg.Verify(pub, Encoding.UTF8.GetBytes(signableCanon), sigBytes))
                Fail("Invalid signature");

            // Anti-replay journal for scope=once
            var nonceTtl = TimeSpan.FromHours(24);
            var journal = new NonceJournalStore(NonceJournalFile);

            var replayKey = $"{decision.nonce}:{decision.artifactHash}";

            if (string.Equals(decision.scope, "once", StringComparison.Ordinal))
            {
                if (journal.Seen(replayKey, now, nonceTtl))
                    Fail("Replay detected (nonce already seen)");

                journal.Record(replayKey, now);
                journal.CompactIfNeeded(now, nonceTtl, maxBytes: 2 * 1024 * 1024);
            }
            else if (string.Equals(decision.scope, "timebox", StringComparison.Ordinal) ||
                     string.Equals(decision.scope, "session", StringComparison.Ordinal))
            {
                // demo policy: timebox/session rely on expiresAt; you can still optionally record nonce.
            }
            else
            {
                Fail($"Unsupported scope: {decision.scope}");
            }

            Console.WriteLine("✅ Decision verified and bound to artifactHash.");
            Console.WriteLine($"Decision: {decision.decision}  Scope: {decision.scope}");
            Console.WriteLine($"ArtifactType: {artifactWire.artifactType}");
            Console.WriteLine($"RepoRef: {artifactWire.repoRef}");
            Console.WriteLine($"ArtifactHash: {artifactWire.artifactHash}");

            if (string.Equals(decision.decision, "allow", StringComparison.Ordinal))
            {
                Console.WriteLine("🟢 ENFORCER RESULT: ALLOW");
                Environment.Exit(0);
            }

            if (string.Equals(decision.decision, "deny", StringComparison.Ordinal))
            {
                Console.WriteLine("🔴 ENFORCER RESULT: DENY");
                Environment.Exit(2);
            }

            Fail($"Unknown decision value: {decision.decision}");
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

        private static void Fail(string msg)
        {
            Console.WriteLine("❌ REJECT: " + msg);
            Environment.Exit(1);
        }

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