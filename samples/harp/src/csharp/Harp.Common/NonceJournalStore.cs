using System.Text.Json;

namespace Harp.Common
{
    public sealed class NonceJournalStore
    {
        private readonly string _path;
        private readonly string _compactPath;

        // key = nonce + ":" + artifactHash
        private readonly Dictionary<string, DateTimeOffset> _active = new(StringComparer.Ordinal);

        public NonceJournalStore(string path)
        {
            _path = path;
            _compactPath = path + ".compact";
            Load();
        }

        public bool Seen(string replayKey, DateTimeOffset now, TimeSpan ttl)
        {
            PruneInMemory(now, ttl);
            return _active.ContainsKey(replayKey);
        }

        public void Record(string replayKey, DateTimeOffset now)
        {
            _active[replayKey] = now;
            AppendLine(new JournalEntry { k = replayKey, ts = now });
        }

        public void CompactIfNeeded(DateTimeOffset now, TimeSpan ttl, long maxBytes = 2 * 1024 * 1024)
        {
            PruneInMemory(now, ttl);

            var fi = new FileInfo(_path);
            if (!fi.Exists || fi.Length < maxBytes) return;

            // Write compact file, then replace
            using (var fs = new FileStream(_compactPath, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var sw = new StreamWriter(fs))
            {
                foreach (var kv in _active)
                {
                    var line = JsonSerializer.Serialize(new JournalEntry { k = kv.Key, ts = kv.Value });
                    sw.WriteLine(line);
                }
            }

            // Replace atomically-ish
            File.Copy(_compactPath, _path, overwrite: true);
            File.Delete(_compactPath);
        }

        // ---------------- internals ----------------

        private void Load()
        {
            if (!File.Exists(_path)) return;

            foreach (var line in File.ReadLines(_path))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var e = JsonSerializer.Deserialize<JournalEntry>(line);
                    if (e?.k is null) continue;
                    _active[e.k] = e.ts;
                }
                catch
                {
                    // ignore malformed lines; journal is append-only, partial writes can happen
                }
            }
        }

        private void AppendLine(string line)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path)) ?? ".");
            using var fs = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.Read);
            using var sw = new StreamWriter(fs);
            sw.WriteLine(line);
            sw.Flush();
            fs.Flush(flushToDisk: true);
        }

        private void AppendLine(JournalEntry entry) => AppendLine(JsonSerializer.Serialize(entry));

        private void PruneInMemory(DateTimeOffset now, TimeSpan ttl)
        {
            // TTL-based pruning (simple)
            var cutoff = now - ttl;
            var remove = new List<string>();

            foreach (var kv in _active)
            {
                if (kv.Value < cutoff)
                    remove.Add(kv.Key);
            }

            foreach (var k in remove)
                _active.Remove(k);
        }

        private sealed class JournalEntry
        {
            // short field names to keep file small
            public required string k { get; set; }          // replayKey
            public DateTimeOffset ts { get; set; }          // first-seen timestamp
        }
    }
}