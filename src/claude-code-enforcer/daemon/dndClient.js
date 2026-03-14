"use strict";

/**
 * DND (Do Not Disturb) policy evaluation for Claude Code enforcer.
 * Port of cursor's dndClient.ts — evaluates workspace and action-level DND policies
 * before submitting artifacts to the gateway.
 *
 * Endpoint: GET /v1/policy/dnd/effective
 */
const http = require("http");
const https = require("https");

const CACHE_TTL_MS = 15_000; // 15s

/** @type {Map<string, { fetchedAt: number, entries: Array }>} */
const _cache = new Map();

function cacheKey(workspaceId, enforcerId, sessionId) {
  return `${workspaceId}::${enforcerId}::${sessionId || "-"}`;
}

/**
 * Evaluate DND policies for a given action.
 * @param {{ endpointUrl: string, workspaceId: string, enforcerId: string, sessionId?: string, authToken?: string }} ctx
 * @param {{ actionType: string, commandText: string }} action
 * @param {(msg: string) => void} [log]
 * @returns {Promise<{ decision: "approve"|"reject", policyId: string, policyMode: string, scope: string } | null>}
 */
async function evaluateDndForAction(ctx, action, log) {
  try {
    const policies = await getEffectivePolicies(ctx, log);
    if (policies.length === 0) return null;

    const now = Date.now();
    const active = policies.filter(p => {
      const exp = Date.parse(p.policy.expiresAt);
      return !Number.isNaN(exp) && exp > now;
    });
    if (active.length === 0) return null;

    // Precedence: action deny > workspace deny > action approve > workspace approve
    const classified = classifyPolicies(active);

    const actionDeny = findBestActionMatch(classified.actionDeny, action);
    if (actionDeny) return toResult("reject", actionDeny);

    const wsDeny = pickNewest(classified.workspaceDeny);
    if (wsDeny) return toResult("reject", wsDeny);

    const actionApprove = findBestActionMatch(classified.actionApprove, action);
    if (actionApprove) return toResult("approve", actionApprove);

    const wsApprove = pickNewest(classified.workspaceApprove);
    if (wsApprove) return toResult("approve", wsApprove);

    return null;
  } catch {
    return null;
  }
}

async function getEffectivePolicies(ctx, log) {
  const key = cacheKey(ctx.workspaceId, ctx.enforcerId, ctx.sessionId);
  const cached = _cache.get(key);
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
    return cached.entries;
  }

  const base = ctx.endpointUrl.replace(/\/$/, "");
  const params = new URLSearchParams({
    enforcerId: ctx.enforcerId,
    workspaceId: ctx.workspaceId,
  });
  if (ctx.sessionId) params.set("sessionId", ctx.sessionId);
  const url = `${base}/v1/policy/dnd/effective?${params.toString()}`;

  try {
    const result = await httpGet(url, ctx.authToken);
    const arr = Array.isArray(result.body) ? result.body : [];
    const entries = [];
    for (const raw of arr) {
      if (!raw || typeof raw !== "object") continue;
      if (!raw.requestId || !raw.objectType || !raw.workspaceId || !raw.enforcerId || !raw.policyMode || !raw.expiresAt) continue;
      entries.push({
        policy: raw,
        scope: raw.objectType === "airlock.dnd.action" ? "action" : "workspace",
      });
    }
    _cache.set(key, { fetchedAt: Date.now(), entries });
    return entries;
  } catch (e) {
    if (log) log(`DND fetch error: ${e.message || e}`);
    const entries = [];
    _cache.set(key, { fetchedAt: Date.now(), entries });
    return entries;
  }
}

function httpGet(url, token) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const transport = parsed.protocol === "https:" ? https : http;
    const headers = { Accept: "application/json" };
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const req = transport.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: "GET",
        headers,
        timeout: 10_000,
      },
      (res) => {
        let raw = "";
        res.on("data", (c) => (raw += c));
        res.on("end", () => {
          if (res.statusCode >= 200 && res.statusCode < 300 && raw) {
            try {
              const json = JSON.parse(raw);
              resolve({ status: res.statusCode, body: json.body || json });
            } catch {
              resolve({ status: res.statusCode, body: [] });
            }
          } else {
            resolve({ status: res.statusCode || 500, body: [] });
          }
        });
      }
    );
    req.on("timeout", () => { req.destroy(); reject(new Error("DND request timeout")); });
    req.on("error", reject);
    req.end();
  });
}

function classifyPolicies(entries) {
  const workspaceDeny = [], workspaceApprove = [], actionDeny = [], actionApprove = [];
  for (const e of entries) {
    const mode = (e.policy.policyMode || "").toLowerCase();
    const isDeny = mode === "deny_all";
    const isApprove = mode === "approve_all";
    if (!isDeny && !isApprove) continue;
    if (e.scope === "workspace") {
      (isDeny ? workspaceDeny : workspaceApprove).push(e);
    } else {
      (isDeny ? actionDeny : actionApprove).push(e);
    }
  }
  return { workspaceDeny, workspaceApprove, actionDeny, actionApprove };
}

function findBestActionMatch(candidates, action) {
  if (candidates.length === 0) return null;
  const argv = action.commandText.split(/\s+/).filter(Boolean);
  if (argv.length === 0) return null;

  let best = null, bestPrefixLen = -1, bestCreatedAt = 0;
  for (const e of candidates) {
    const sel = e.policy.actionSelector;
    if (!sel || !sel.argvPrefix || sel.argvPrefix.length === 0) continue;
    const selectorTokens = sel.argvPrefix.flatMap(p => p.split(/\s+/)).filter(Boolean);
    if (!matchesPrefix(argv, selectorTokens)) continue;

    const prefixLen = sel.argvPrefix.length;
    const createdAtMs = e.policy.createdAt ? Date.parse(e.policy.createdAt) : 0;
    if (prefixLen > bestPrefixLen || (prefixLen === bestPrefixLen && createdAtMs > bestCreatedAt)) {
      best = e;
      bestPrefixLen = prefixLen;
      bestCreatedAt = createdAtMs;
    }
  }
  return best;
}

function matchesPrefix(argv, prefix) {
  if (argv.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (argv[i] !== prefix[i]) return false;
  }
  return true;
}

function pickNewest(entries) {
  if (entries.length === 0) return null;
  let best = entries[0], bestCreatedAt = best.policy.createdAt ? Date.parse(best.policy.createdAt) : 0;
  for (let i = 1; i < entries.length; i++) {
    const c = entries[i];
    const t = c.policy.createdAt ? Date.parse(c.policy.createdAt) : 0;
    if (t > bestCreatedAt) { best = c; bestCreatedAt = t; }
  }
  return best;
}

function toResult(decision, entry) {
  return {
    decision,
    policyId: entry.policy.requestId,
    policyMode: entry.policy.policyMode,
    scope: entry.scope,
  };
}

module.exports = { evaluateDndForAction };
