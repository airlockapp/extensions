using System.Security.Cryptography;
using NSec.Cryptography;

namespace Harp.Common
{
    public static class NsecAead
    {
        // Detached mode = return ciphertext and tag separately.
        // Under the hood NSec produces ciphertext||tag, and we split it.
        public static (byte[] nonce, byte[] ciphertext, byte[] tag) XChaChaEncryptDetached(
            byte[] key32,
            byte[] plaintext,
            byte[] associatedData)
        {
            if (key32 is null) throw new ArgumentNullException(nameof(key32));
            if (plaintext is null) throw new ArgumentNullException(nameof(plaintext));
            if (associatedData is null) associatedData = Array.Empty<byte>();

            var alg = AeadAlgorithm.XChaCha20Poly1305;
            if (key32.Length != alg.KeySize)
                throw new ArgumentException($"Key must be {alg.KeySize} bytes for {alg}.", nameof(key32));

            byte[] nonce = RandomNumberGenerator.GetBytes(alg.NonceSize);

            // Import raw symmetric key bytes into an NSec Key object
            using var key = Key.Import(alg, key32, KeyBlobFormat.RawSymmetricKey);

            // Encrypt returns combined ciphertext: (ciphertext || tag)
            byte[] combined = alg.Encrypt(key, nonce, associatedData, plaintext);

            int tagSize = alg.TagSize;
            if (combined.Length < tagSize)
                throw new CryptographicException("Ciphertext is shorter than tag size.");

            int ctLen = combined.Length - tagSize;
            byte[] ciphertext = new byte[ctLen];
            byte[] tag = new byte[tagSize];

            Buffer.BlockCopy(combined, 0, ciphertext, 0, ctLen);
            Buffer.BlockCopy(combined, ctLen, tag, 0, tagSize);

            // Zero combined buffer since it contained tag too
            CryptographicOperations.ZeroMemory(combined);

            return (nonce, ciphertext, tag);
        }

        public static byte[] XChaChaDecryptDetached(
            byte[] key32,
            byte[] nonce,
            byte[] ciphertext,
            byte[] tag,
            byte[] associatedData)
        {
            if (key32 is null) throw new ArgumentNullException(nameof(key32));
            if (nonce is null) throw new ArgumentNullException(nameof(nonce));
            if (ciphertext is null) throw new ArgumentNullException(nameof(ciphertext));
            if (tag is null) throw new ArgumentNullException(nameof(tag));
            if (associatedData is null) associatedData = Array.Empty<byte>();

            var alg = AeadAlgorithm.XChaCha20Poly1305;

            if (key32.Length != alg.KeySize)
                throw new ArgumentException($"Key must be {alg.KeySize} bytes for {alg}.", nameof(key32));
            if (nonce.Length != alg.NonceSize)
                throw new ArgumentException($"Nonce must be {alg.NonceSize} bytes for {alg}.", nameof(nonce));
            if (tag.Length != alg.TagSize)
                throw new ArgumentException($"Tag must be {alg.TagSize} bytes for {alg}.", nameof(tag));

            using var key = Key.Import(alg, key32, KeyBlobFormat.RawSymmetricKey);

            // Recombine ciphertext||tag for NSec Decrypt
            byte[] combined = new byte[ciphertext.Length + tag.Length];
            Buffer.BlockCopy(ciphertext, 0, combined, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, combined, ciphertext.Length, tag.Length);

            // Decrypt returns null on authentication failure (tamper/wrong key/AAD)
            byte[]? plaintext = alg.Decrypt(key, nonce, associatedData, combined);

            CryptographicOperations.ZeroMemory(combined);

            if (plaintext is null)
                throw new CryptographicException("AEAD authentication failed.");

            return plaintext;
        }
    }
}