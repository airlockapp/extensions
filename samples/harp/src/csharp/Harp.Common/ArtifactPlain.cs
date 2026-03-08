namespace Harp.Common
{
    public sealed class ArtifactPlain
    {
        public required string requestId { get; set; }
        public string? sessionId { get; set; }
        public required string artifactType { get; set; }     // e.g. command.review
        public required string repoRef { get; set; }          // opaque
        public string? baseRevision { get; set; }

        public required DateTimeOffset createdAt { get; set; }
        public required DateTimeOffset expiresAt { get; set; }

        public required object payload { get; set; }          // plaintext prior to encryption

        public required string artifactHashAlg { get; set; }  // SHA-256
        public required string artifactHash { get; set; }     // hex sha256

        public object? metadata { get; set; }
        public Dictionary<string, object?>? extensions { get; set; }
    }
}
