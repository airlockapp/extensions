/**
 * State persistence for pairing results.
 *
 * After a successful pairing claim, we need to persist:
 * - routingToken (used in artifact metadata for routing to approver)
 * - encryptionKey (AES-256-GCM key for artifact encryption)
 * - pairedKeys (Ed25519 public keys for decision signature verification)
 *
 * State is stored as a JSON file in the working directory.
 * This is similar to the Claude Code enforcer's config.storeRoutingTokenAsync() pattern.
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import type { PairedKeyEntry } from "./crypto.js";

// ── Types ───────────────────────────────────────────────────────

export interface AirlockPairingState {
  /** Routing token from completed pairing. */
  routingToken: string;
  /** AES-256-GCM encryption key (base64url) derived via X25519 ECDH. */
  encryptionKey: string;
  /** Paired approver public keys, keyed by signerKeyId. */
  pairedKeys: Record<string, PairedKeyEntry>;
  /** Timestamp of when pairing was completed. */
  pairedAt: string;
  /** The pairing nonce used. */
  pairingNonce: string;
}

// ── Constants ───────────────────────────────────────────────────

const STATE_DIR = ".airlock";
const STATE_FILE = "pairing-state.json";

// ── State Operations ────────────────────────────────────────────

function getStatePath(): string {
  return join(process.cwd(), STATE_DIR, STATE_FILE);
}

/**
 * Load persisted pairing state from disk.
 * Returns null if no state file exists or it's corrupted.
 */
export async function loadPairingState(): Promise<AirlockPairingState | null> {
  try {
    const raw = await readFile(getStatePath(), "utf-8");
    const state = JSON.parse(raw) as AirlockPairingState;

    // Basic validation
    if (!state.routingToken || !state.encryptionKey) {
      return null;
    }

    return state;
  } catch {
    return null;
  }
}

/**
 * Save pairing state to disk.
 * Creates the .airlock directory if it doesn't exist.
 */
export async function savePairingState(state: AirlockPairingState): Promise<void> {
  const statePath = getStatePath();
  const dir = dirname(statePath);

  await mkdir(dir, { recursive: true });
  await writeFile(statePath, JSON.stringify(state, null, 2), "utf-8");
}

/**
 * Clear persisted pairing state (e.g. on pairing revocation).
 */
export async function clearPairingState(): Promise<void> {
  try {
    const { unlink } = await import("node:fs/promises");
    await unlink(getStatePath());
  } catch {
    // File might not exist, that's fine
  }
}

/**
 * Get paired keys from persisted state.
 * Returns an empty record if no state is available.
 */
export async function loadPairedKeys(): Promise<Record<string, PairedKeyEntry>> {
  const state = await loadPairingState();
  return state?.pairedKeys ?? {};
}
