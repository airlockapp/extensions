namespace Harp.Common
{
    public sealed class Decision
    {
        public required string requestId { get; set; }
        public required string artifactHashAlg { get; set; }
        public required string artifactHash { get; set; }
        public required string repoRef { get; set; }

        public required string decision { get; set; }     // allow|deny
        public required string scope { get; set; }        // once|timebox|session
        public required DateTimeOffset expiresAt { get; set; }
        public required string nonce { get; set; }        // base64url recommended

        public required string sigAlg { get; set; }       // Ed25519
        public required string signerKeyId { get; set; }
        public required string signature { get; set; }    // base64url over DecisionSignable canonical JSON
    }
}
