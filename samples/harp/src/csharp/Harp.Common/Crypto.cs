using LibSodium;
using NSec.Cryptography;
using System.Security.Cryptography;
using System.Text;

namespace Harp.Common
{
    public static partial class Crypto
    {
        // ---------------- Base64url ----------------
        public static string ToB64Url(byte[] bytes)
            => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        public static byte[] FromB64Url(string s)
        {
            s = s.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
            }
            return Convert.FromBase64String(s);
        }

        // ---------------- Hashing ----------------
        public static string Sha256Hex(string s)
        {
            var bytes = Encoding.UTF8.GetBytes(s);
            var hash = SHA256.HashData(bytes);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        // ---------------- HKDF(SHA-256) ----------------
        // Minimal HKDF implementation: RFC 5869
        public static byte[] HkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length)
        {
            // Extract
            using var hmac = new HMACSHA256(salt);
            var prk = hmac.ComputeHash(ikm);

            // Expand
            var okm = new byte[length];
            var t = Array.Empty<byte>();
            int written = 0;
            byte counter = 1;

            using var hmac2 = new HMACSHA256(prk);
            while (written < length)
            {
                hmac2.Initialize();
                hmac2.TransformBlock(t, 0, t.Length, null, 0);
                hmac2.TransformBlock(info, 0, info.Length, null, 0);
                hmac2.TransformFinalBlock(new[] { counter }, 0, 1);
                t = hmac2.Hash ?? throw new InvalidOperationException("HKDF expansion failed");

                int toCopy = Math.Min(t.Length, length - written);
                Buffer.BlockCopy(t, 0, okm, written, toCopy);
                written += toCopy;
                counter++;
            }

            CryptographicOperations.ZeroMemory(prk);
            return okm;
        }

        // ---------------- ECDH P-256 ----------------
        public static (string pubSpkiB64Url, byte[] privPkcs8) CreateEcdhP256Keypair()
        {
            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var pub = ecdh.ExportSubjectPublicKeyInfo();
            var priv = ecdh.ExportPkcs8PrivateKey();
            return (ToB64Url(pub), priv);
        }

        public static byte[] DeriveSharedSecretEcdhP256(byte[] myPrivPkcs8, byte[] peerPubSpki)
        {
            using var mine = ECDiffieHellman.Create();
            mine.ImportPkcs8PrivateKey(myPrivPkcs8, out _);

            using var peer = ECDiffieHellman.Create();
            peer.ImportSubjectPublicKeyInfo(peerPubSpki, out _);

            // derive key material
            return mine.DeriveKeyMaterial(peer.PublicKey);
        }

        // ---------------- AES-256-GCM ----------------
        public static (byte[] nonce12, byte[] ciphertext, byte[] tag16) AesGcmEncrypt(byte[] key32, byte[] plaintext, byte[] aad)
        {
            var nonce = RandomNumberGenerator.GetBytes(12);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];

            using var aes = new AesGcm(key32, 16);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            return (nonce, ciphertext, tag);
        }

        public static byte[] AesGcmDecrypt(byte[] key32, byte[] nonce12, byte[] ciphertext, byte[] tag16, byte[] aad)
        {
            var plaintext = new byte[ciphertext.Length];
            using var aes = new AesGcm(key32, 16);
            aes.Decrypt(nonce12, ciphertext, tag16, plaintext, aad);
            return plaintext;
        }

        // ---------------- Ed25519 (NSec) ----------------
        public static (string pubB64Url, string privB64Url) CreateEd25519Keypair()
        {
            var algo = SignatureAlgorithm.Ed25519;
            using var key = new Key(algo, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

            var pub = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
            var priv = key.Export(KeyBlobFormat.RawPrivateKey);

            return (ToB64Url(pub), ToB64Url(priv));
        }

        public static string Ed25519Sign(string privRawB64Url, byte[] message)
        {
            var algo = SignatureAlgorithm.Ed25519;
            var privRaw = FromB64Url(privRawB64Url);
            using var key = Key.Import(algo, privRaw, KeyBlobFormat.RawPrivateKey);
            var sig = algo.Sign(key, message);
            return ToB64Url(sig);
        }

        public static bool Ed25519Verify(string pubRawB64Url, byte[] message, string sigB64Url)
        {
            var algo = SignatureAlgorithm.Ed25519;
            var pubRaw = FromB64Url(pubRawB64Url);
            var sig = FromB64Url(sigB64Url);

            var pk = PublicKey.Import(algo, pubRaw, KeyBlobFormat.RawPublicKey);
            return algo.Verify(pk, message, sig);
        }
    }
}