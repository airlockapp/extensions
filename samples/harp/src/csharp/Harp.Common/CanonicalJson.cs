using System.Text.Json;
using Org.Webpki.JsonCanonicalizer;

namespace Harp.Common
{
    public static class CanonicalJson
    {
        // IMPORTANT:
        // - We still serialize objects with System.Text.Json first (no indentation).
        // - Then we run JCS canonicalization (RFC 8785) over the resulting JSON text.
        //
        // JCS handles: deterministic object member ordering, number rendering, escaping, etc.
        // This gives you standards-grade canonical bytes for hashing/signing.

        public static readonly JsonSerializerOptions JsonOpts = new()
        {
            PropertyNamingPolicy = null,
            WriteIndented = false,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };

        public static string Canonicalize(object obj)
        {
            var json = JsonSerializer.Serialize(obj, JsonOpts);
            var jcs = new JsonCanonicalizer(json);
            return jcs.GetEncodedString();
        }

        public static byte[] CanonicalizeUtf8(object obj)
        {
            var json = JsonSerializer.Serialize(obj, JsonOpts);
            var jcs = new JsonCanonicalizer(json);
            return jcs.GetEncodedUTF8();
        }

        public static string CanonicalizeJsonString(string json)
        {
            var jcs = new JsonCanonicalizer(json);
            return jcs.GetEncodedString();
        }

        public static byte[] CanonicalizeJsonUtf8(byte[] jsonUtf8)
        {
            var jcs = new JsonCanonicalizer(jsonUtf8);
            return jcs.GetEncodedUTF8();
        }
    }
}