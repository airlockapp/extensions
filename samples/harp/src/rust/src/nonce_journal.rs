//! Append-only nonce replay journal with TTL pruning and compaction.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use chrono::{DateTime, Duration, Utc};

#[derive(Serialize, Deserialize)]
struct Entry {
    k: String,
    ts: String,
}

pub struct NonceJournalStore {
    path: PathBuf,
    compact_path: PathBuf,
    active: HashMap<String, DateTime<Utc>>,
}

impl NonceJournalStore {
    pub fn new(path: &str) -> io::Result<Self> {
        let mut store = Self {
            path: PathBuf::from(path),
            compact_path: PathBuf::from(format!("{}.compact", path)),
            active: HashMap::new(),
        };
        store.load()?;
        Ok(store)
    }

    /// Check whether `replay_key` has been seen within the TTL window.
    pub fn seen(&mut self, replay_key: &str, now: DateTime<Utc>, ttl: Duration) -> bool {
        self.prune_in_memory(now, ttl);
        self.active.contains_key(replay_key)
    }

    /// Record a new replay key.
    pub fn record(&mut self, replay_key: &str, now: DateTime<Utc>) -> io::Result<()> {
        self.active.insert(replay_key.to_string(), now);
        let entry = Entry {
            k: replay_key.to_string(),
            ts: now.to_rfc3339(),
        };
        let line = serde_json::to_string(&entry).unwrap();
        self.append_line(&line)
    }

    /// Compact the journal file if it exceeds `max_bytes`.
    pub fn compact_if_needed(
        &mut self,
        now: DateTime<Utc>,
        ttl: Duration,
        max_bytes: u64,
    ) -> io::Result<()> {
        self.prune_in_memory(now, ttl);

        if !self.path.exists() {
            return Ok(());
        }
        let size = fs::metadata(&self.path)?.len();
        if size < max_bytes {
            return Ok(());
        }

        let mut content = String::new();
        for (k, ts) in &self.active {
            let entry = Entry {
                k: k.clone(),
                ts: ts.to_rfc3339(),
            };
            content.push_str(&serde_json::to_string(&entry).unwrap());
            content.push('\n');
        }

        fs::write(&self.compact_path, &content)?;
        fs::write(&self.path, &content)?;
        let _ = fs::remove_file(&self.compact_path);

        Ok(())
    }

    fn load(&mut self) -> io::Result<()> {
        if !self.path.exists() {
            return Ok(());
        }

        let file = fs::File::open(&self.path)?;
        let reader = io::BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<Entry>(&line) {
                if !entry.k.is_empty() {
                    if let Ok(ts) = DateTime::parse_from_rfc3339(&entry.ts) {
                        self.active.insert(entry.k, ts.with_timezone(&Utc));
                    }
                }
            }
        }

        Ok(())
    }

    fn append_line(&self, line: &str) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;

        writeln!(file, "{}", line)?;
        file.flush()?;
        file.sync_all()
    }

    fn prune_in_memory(&mut self, now: DateTime<Utc>, ttl: Duration) {
        let cutoff = now - ttl;
        self.active.retain(|_, ts| *ts >= cutoff);
    }
}
