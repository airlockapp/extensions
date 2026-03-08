namespace Harp.Common
{
    // The signable view (no signature field)
    public sealed class DecisionSignable
    {
        public required string requestId { get; set; }
        public required string artifactHashAlg { get; set; }
        public required string artifactHash { get; set; }
        public required string repoRef { get; set; }

        public required string decision { get; set; }
        public required string scope { get; set; }
        public required DateTimeOffset expiresAt { get; set; }
        public required string nonce { get; set; }

        public required string sigAlg { get; set; }
        public required string signerKeyId { get; set; }

        public object? policyHints { get; set; }
    }
}
