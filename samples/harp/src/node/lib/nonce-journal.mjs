// lib/nonce-journal.mjs
// Append-only nonce replay journal with TTL pruning and compaction.
// Mirrors Harp.Common/NonceJournalStore.cs

import {
    existsSync, readFileSync, appendFileSync,
    writeFileSync, statSync, mkdirSync, unlinkSync,
} from 'node:fs';
import { dirname } from 'node:path';

export class NonceJournalStore {
    /** @type {string} */
    #path;

    /** @type {string} */
    #compactPath;

    /** @type {Map<string, Date>} key = replayKey, value = first-seen timestamp */
    #active = new Map();

    /**
     * @param {string} path - Path to the nonce journal file
     */
    constructor(path) {
        this.#path = path;
        this.#compactPath = path + '.compact';
        this.#load();
    }

    /**
     * Check whether replayKey has been seen within the TTL window.
     * @param {string} replayKey
     * @param {Date} now
     * @param {number} ttlMs - TTL in milliseconds
     * @returns {boolean}
     */
    seen(replayKey, now, ttlMs) {
        this.#pruneInMemory(now, ttlMs);
        return this.#active.has(replayKey);
    }

    /**
     * Record a new replay key.
     * @param {string} replayKey
     * @param {Date} now
     */
    record(replayKey, now) {
        this.#active.set(replayKey, now);
        this.#appendLine(JSON.stringify({ k: replayKey, ts: now.toISOString() }));
    }

    /**
     * Compact the journal file if it exceeds maxBytes.
     * @param {Date} now
     * @param {number} ttlMs
     * @param {number} [maxBytes=2097152]
     */
    compactIfNeeded(now, ttlMs, maxBytes = 2 * 1024 * 1024) {
        this.#pruneInMemory(now, ttlMs);

        if (!existsSync(this.#path)) return;
        const { size } = statSync(this.#path);
        if (size < maxBytes) return;

        // Write compact file, then replace
        const lines = [...this.#active.entries()]
            .map(([k, ts]) => JSON.stringify({ k, ts: ts.toISOString() }))
            .join('\n') + '\n';

        writeFileSync(this.#compactPath, lines, 'utf8');
        writeFileSync(this.#path, lines, 'utf8');

        try { unlinkSync(this.#compactPath); } catch { /* ignore */ }
    }

    // ──────────────── internals ────────────────

    #load() {
        if (!existsSync(this.#path)) return;

        const content = readFileSync(this.#path, 'utf8');
        for (const line of content.split('\n')) {
            if (!line.trim()) continue;
            try {
                const e = JSON.parse(line);
                if (e?.k) this.#active.set(e.k, new Date(e.ts));
            } catch {
                // ignore malformed lines; journal is append-only, partial writes can happen
            }
        }
    }

    #appendLine(line) {
        mkdirSync(dirname(this.#path), { recursive: true });
        appendFileSync(this.#path, line + '\n', 'utf8');
    }

    #pruneInMemory(now, ttlMs) {
        const cutoff = new Date(now.getTime() - ttlMs);
        for (const [k, ts] of this.#active) {
            if (ts < cutoff) this.#active.delete(k);
        }
    }
}
