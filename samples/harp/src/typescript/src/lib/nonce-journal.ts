/**
 * Append-only nonce replay journal with TTL pruning and compaction.
 * Mirrors Harp.Common/NonceJournalStore.cs.
 */

import {
    existsSync, readFileSync, appendFileSync,
    writeFileSync, statSync, mkdirSync, unlinkSync,
} from "node:fs";
import { dirname } from "node:path";

interface JournalEntry {
    readonly k: string;
    readonly ts: string;
}

export class NonceJournalStore {
    readonly #path: string;
    readonly #compactPath: string;
    readonly #active: Map<string, Date> = new Map();

    constructor(path: string) {
        this.#path = path;
        this.#compactPath = path + ".compact";
        this.#load();
    }

    /** Check whether replayKey has been seen within the TTL window. */
    seen(replayKey: string, now: Date, ttlMs: number): boolean {
        this.#pruneInMemory(now, ttlMs);
        return this.#active.has(replayKey);
    }

    /** Record a new replay key. */
    record(replayKey: string, now: Date): void {
        this.#active.set(replayKey, now);
        this.#appendLine(JSON.stringify({ k: replayKey, ts: now.toISOString() } satisfies JournalEntry));
    }

    /** Compact the journal file if it exceeds maxBytes. */
    compactIfNeeded(now: Date, ttlMs: number, maxBytes: number = 2 * 1024 * 1024): void {
        this.#pruneInMemory(now, ttlMs);

        if (!existsSync(this.#path)) return;
        const { size } = statSync(this.#path);
        if (size < maxBytes) return;

        const lines = [...this.#active.entries()]
            .map(([k, ts]) => JSON.stringify({ k, ts: ts.toISOString() } satisfies JournalEntry))
            .join("\n") + "\n";

        writeFileSync(this.#compactPath, lines, "utf8");
        writeFileSync(this.#path, lines, "utf8");

        try { unlinkSync(this.#compactPath); } catch { /* ignore */ }
    }

    // ──────────────── internals ────────────────

    #load(): void {
        if (!existsSync(this.#path)) return;

        const content = readFileSync(this.#path, "utf8");
        for (const line of content.split("\n")) {
            if (!line.trim()) continue;
            try {
                const entry: JournalEntry = JSON.parse(line);
                if (entry?.k) this.#active.set(entry.k, new Date(entry.ts));
            } catch {
                // ignore malformed lines
            }
        }
    }

    #appendLine(line: string): void {
        mkdirSync(dirname(this.#path), { recursive: true });
        appendFileSync(this.#path, line + "\n", "utf8");
    }

    #pruneInMemory(now: Date, ttlMs: number): void {
        const cutoff = new Date(now.getTime() - ttlMs);
        for (const [k, ts] of this.#active) {
            if (ts < cutoff) this.#active.delete(k);
        }
    }
}
