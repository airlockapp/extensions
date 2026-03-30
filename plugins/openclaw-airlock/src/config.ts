/**
 * Airlock Plugin Config — parse, validate, and apply defaults.
 *
 * Config comes from OpenClaw's plugin config mechanism (openclaw.plugin.json schema).
 * Auth: PAT + ClientId/ClientSecret. Pairing: pre-generated device code.
 */

/** Strongly-typed config for the Airlock OpenClaw plugin. */
export interface AirlockConfig {
  /** Airlock Gateway base URL (e.g. "https://gw.airlocks.io"). */
  gatewayUrl: string;
  /** Unique identifier for this enforcer instance. */
  enforcerId: string;
  /** Personal Access Token for user authentication. */
  pat?: string;
  /** Enforcer App Client ID. */
  clientId?: string;
  /** Enforcer App Client Secret. */
  clientSecret?: string;
  /** Pre-generated device pairing code. */
  pairingCode?: string;
  /** Human-readable workspace name. */
  workspaceName: string;
  /** Approval timeout in milliseconds (default: 300000 = 5 min). */
  timeoutMs: number;
  /** Decision poll interval in milliseconds (default: 3000). */
  pollIntervalMs: number;
  /** Behavior on timeout/error: "open" = allow, "closed" = block. */
  failMode: "open" | "closed";
  /** Tool names requiring approval (empty = none protected, opt-in). */
  protectedTools: string[];
  /** How to wait for decisions: "poll" (default) or "webhook" (future). */
  executionMode: "poll" | "webhook";

  // ── Runtime state (set after pairing claim) ──
  /** Routing token from completed pairing. */
  routingToken?: string;
  /** AES-256-GCM encryption key (base64url) derived via X25519 ECDH. */
  encryptionKey?: string;
}

/**
 * Parse raw config from OpenClaw plugin context, validate required fields,
 * and apply defaults.
 *
 * @throws Error if required fields are missing or values are invalid.
 */
export function loadAndValidateConfig(raw: Record<string, unknown>): AirlockConfig {
  // ── Required fields ──
  const gatewayUrl = requireString(raw, "gatewayUrl", "Gateway URL is required");
  if (!/^https?:\/\//i.test(gatewayUrl)) {
    throw new ConfigError("gatewayUrl must start with http:// or https://");
  }

  const enforcerId = requireString(raw, "enforcerId", "Enforcer ID is required");

  // ── Auth: at least PAT or clientId+clientSecret ──
  const pat = optionalString(raw, "pat");
  const clientId = optionalString(raw, "clientId");
  const clientSecret = optionalString(raw, "clientSecret");

  if (!pat && !clientId) {
    throw new ConfigError(
      "Authentication required: provide either 'pat' (Personal Access Token) " +
      "or 'clientId' + 'clientSecret' (Enforcer App credentials)"
    );
  }

  if (clientId && !clientSecret) {
    throw new ConfigError("'clientSecret' is required when 'clientId' is provided");
  }

  // ── Optional fields with defaults ──
  const pairingCode = optionalString(raw, "pairingCode");
  const workspaceName = optionalString(raw, "workspaceName") ?? "OpenClaw Workspace";
  const timeoutMs = optionalNumber(raw, "timeoutMs") ?? 300_000;
  const pollIntervalMs = Math.max(1000, optionalNumber(raw, "pollIntervalMs") ?? 3000);

  const rawFailMode = optionalString(raw, "failMode") ?? "closed";
  if (rawFailMode !== "open" && rawFailMode !== "closed") {
    throw new ConfigError(`failMode must be "open" or "closed", got "${rawFailMode}"`);
  }

  const rawExecMode = optionalString(raw, "executionMode") ?? "poll";
  if (rawExecMode !== "poll" && rawExecMode !== "webhook") {
    throw new ConfigError(`executionMode must be "poll" or "webhook", got "${rawExecMode}"`);
  }
  if (rawExecMode === "webhook") {
    throw new ConfigError("Webhook mode is not implemented yet (planned for Sprint 26+). Use 'poll'.");
  }

  const rawProtectedTools = raw["protectedTools"];
  let protectedTools: string[] = [];
  if (Array.isArray(rawProtectedTools)) {
    protectedTools = rawProtectedTools
      .map((t) => String(t).trim())
      .filter((t) => t.length > 0);
  }

  return {
    gatewayUrl: gatewayUrl.replace(/\/$/, ""),
    enforcerId,
    pat,
    clientId,
    clientSecret,
    pairingCode,
    workspaceName,
    timeoutMs,
    pollIntervalMs,
    failMode: rawFailMode,
    protectedTools,
    executionMode: rawExecMode,
  };
}

// ── Helpers ──────────────────────────────────────────────────────

export class ConfigError extends Error {
  constructor(message: string) {
    super(`[Airlock Config] ${message}`);
    this.name = "ConfigError";
  }
}

function requireString(raw: Record<string, unknown>, key: string, errorMsg: string): string {
  const value = raw[key];
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new ConfigError(errorMsg);
  }
  return value.trim();
}

function optionalString(raw: Record<string, unknown>, key: string): string | undefined {
  const value = raw[key];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function optionalNumber(raw: Record<string, unknown>, key: string): number | undefined {
  const value = raw[key];
  if (value === undefined || value === null) return undefined;
  const num = Number(value);
  return Number.isFinite(num) ? num : undefined;
}
