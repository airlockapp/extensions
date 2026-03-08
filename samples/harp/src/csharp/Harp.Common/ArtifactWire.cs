using System;
using System.Collections.Generic;
using System.Text;

namespace Harp.Common
{
    public sealed class ArtifactWire
    {
        // Header fields (plaintext)
        public required string requestId { get; set; }
        public string? sessionId { get; set; }
        public required string artifactType { get; set; }
        public required string repoRef { get; set; }
        public string? baseRevision { get; set; }

        public required DateTimeOffset createdAt { get; set; }
        public required DateTimeOffset expiresAt { get; set; }

        public required string artifactHashAlg { get; set; }
        public required string artifactHash { get; set; }

        public object? metadata { get; set; }
        public Dictionary<string, object?>? extensions { get; set; }

        // Encrypted payload
        public required EncBlob enc { get; set; }
    }
}
