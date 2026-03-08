// Package journal implements an append-only nonce replay journal.
package journal

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type entry struct {
	K  string `json:"k"`
	TS string `json:"ts"`
}

// NonceJournalStore provides file-based nonce replay protection.
type NonceJournalStore struct {
	path        string
	compactPath string
	active      map[string]time.Time
}

// New creates a new NonceJournalStore, loading any existing entries.
func New(path string) (*NonceJournalStore, error) {
	j := &NonceJournalStore{
		path:        path,
		compactPath: path + ".compact",
		active:      make(map[string]time.Time),
	}
	if err := j.load(); err != nil {
		return nil, err
	}
	return j, nil
}

// Seen checks whether replayKey has been seen within the TTL window.
func (j *NonceJournalStore) Seen(replayKey string, now time.Time, ttl time.Duration) bool {
	j.pruneInMemory(now, ttl)
	_, exists := j.active[replayKey]
	return exists
}

// Record records a new replay key.
func (j *NonceJournalStore) Record(replayKey string, now time.Time) error {
	j.active[replayKey] = now
	e := entry{K: replayKey, TS: now.Format(time.RFC3339Nano)}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return j.appendLine(string(b))
}

// CompactIfNeeded compacts the journal file if it exceeds maxBytes.
func (j *NonceJournalStore) CompactIfNeeded(now time.Time, ttl time.Duration, maxBytes int64) error {
	j.pruneInMemory(now, ttl)

	info, err := os.Stat(j.path)
	if err != nil {
		return nil // file doesn't exist, nothing to compact
	}
	if info.Size() < maxBytes {
		return nil
	}

	var lines []string
	for k, ts := range j.active {
		e := entry{K: k, TS: ts.Format(time.RFC3339Nano)}
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		lines = append(lines, string(b))
	}

	content := ""
	for _, line := range lines {
		content += line + "\n"
	}

	if err := os.WriteFile(j.compactPath, []byte(content), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(j.path, []byte(content), 0644); err != nil {
		return err
	}
	os.Remove(j.compactPath)

	return nil
}

func (j *NonceJournalStore) load() error {
	f, err := os.Open(j.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var e entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue // ignore malformed lines
		}
		if e.K != "" {
			ts, err := time.Parse(time.RFC3339Nano, e.TS)
			if err != nil {
				continue
			}
			j.active[e.K] = ts
		}
	}

	return scanner.Err()
}

func (j *NonceJournalStore) appendLine(line string) error {
	if err := os.MkdirAll(filepath.Dir(j.path), 0755); err != nil {
		return fmt.Errorf("journal mkdir: %w", err)
	}

	f, err := os.OpenFile(j.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("journal open: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("journal write: %w", err)
	}
	return f.Sync()
}

func (j *NonceJournalStore) pruneInMemory(now time.Time, ttl time.Duration) {
	cutoff := now.Add(-ttl)
	for k, ts := range j.active {
		if ts.Before(cutoff) {
			delete(j.active, k)
		}
	}
}
