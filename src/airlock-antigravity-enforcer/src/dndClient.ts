import * as vscode from "vscode";

type DndDecision = "approve_all" | "deny_all";

export interface DndMatchResult {
    decision: "approve" | "reject";
    policyId: string;
    policyMode: DndDecision;
    scope: "workspace" | "action";
}

interface DndActionSelector {
    commandFamily?: string;
    argvPrefix?: string[];
}

interface DndPolicyWire {
    requestId: string;
    objectType: string; // airlock.dnd.workspace | airlock.dnd.action
    workspaceId: string;
    sessionId?: string;
    enforcerId: string;
    policyMode: DndDecision | string;
    targetArtifactType?: string;
    actionSelector?: DndActionSelector;
    selectorHash?: string;
    createdAt?: string;
    expiresAt: string;
}

interface DndPolicyCacheEntry {
    policy: DndPolicyWire;
    scope: "workspace" | "action";
}

const CACHE_TTL_MS = 15_000; // 15s — cheap to refresh, keeps behavior snappy

interface CacheKey {
    workspaceId: string;
    enforcerId: string;
    sessionId?: string;
}

interface CacheValue {
    fetchedAt: number;
    entries: DndPolicyCacheEntry[];
}

const _cache = new Map<string, CacheValue>();

function cacheKey(k: CacheKey): string {
    return `${k.workspaceId}::${k.enforcerId}::${k.sessionId ?? "-"}`;
}

function isCacheFresh(v: CacheValue): boolean {
    return Date.now() - v.fetchedAt < CACHE_TTL_MS;
}

export interface DndContext {
    endpointUrl: string;
    workspaceId: string;
    enforcerId: string;
    sessionId?: string;
    authToken?: string;
}

export interface DndAction {
    actionType: string;
    commandText: string;
}

/**
 * Fetch effective DND policies for this enforcer/workspace/session and match against
 * the given action. Returns null if no policy applies.
 */
export async function evaluateDndForAction(
    ctx: DndContext,
    action: DndAction,
    out?: vscode.OutputChannel
): Promise<DndMatchResult | null> {
    try {
        const policies = await getEffectivePolicies(ctx, out);
        if (policies.length === 0) {
            return null;
        }

        const now = Date.now();
        const active = policies.filter(p => {
            const exp = Date.parse(p.policy.expiresAt);
            return !Number.isNaN(exp) && exp > now;
        });
        if (active.length === 0) {
            return null;
        }

        // Precedence:
        // 1) action-level deny
        // 2) workspace-level deny
        // 3) action-level approve
        // 4) workspace-level approve
        const candidates = classifyPolicies(active);

        const actionMatchDeny = findBestActionMatch(candidates.actionDeny, action);
        if (actionMatchDeny) {
            return toResult("reject", actionMatchDeny);
        }

        const workspaceDeny = pickNewest(candidates.workspaceDeny);
        if (workspaceDeny) {
            return toResult("reject", workspaceDeny);
        }

        const actionMatchApprove = findBestActionMatch(candidates.actionApprove, action);
        if (actionMatchApprove) {
            return toResult("approve", actionMatchApprove);
        }

        const workspaceApprove = pickNewest(candidates.workspaceApprove);
        if (workspaceApprove) {
            return toResult("approve", workspaceApprove);
        }
        return null;
    } catch {
        return null;
    }
}

async function getEffectivePolicies(
    ctx: DndContext,
    out?: vscode.OutputChannel
): Promise<DndPolicyCacheEntry[]> {
    const key = cacheKey({
        workspaceId: ctx.workspaceId,
        enforcerId: ctx.enforcerId,
        sessionId: ctx.sessionId
    });

    const cached = _cache.get(key);
    if (cached && isCacheFresh(cached)) {
        return cached.entries;
    }

    const url = new URL("/v1/policy/dnd/effective", ctx.endpointUrl.replace(/\/$/, ""));
    url.searchParams.set("enforcerId", ctx.enforcerId);
    url.searchParams.set("workspaceId", ctx.workspaceId);
    if (ctx.sessionId) {
        url.searchParams.set("sessionId", ctx.sessionId);
    }

    const headers: Record<string, string> = {
        "Accept": "application/json",
    };
    if (ctx.authToken) {
        headers["Authorization"] = `Bearer ${ctx.authToken}`;
    }

    const resp = await fetch(url.toString(), {
        method: "GET",
        headers,
    });

    if (!resp.ok) {
        const entries: DndPolicyCacheEntry[] = [];
        _cache.set(key, { fetchedAt: Date.now(), entries });
        return entries;
    }

    const json = await resp.json() as { body?: unknown };
    const arr = Array.isArray(json.body) ? json.body : [];

    const parsed: DndPolicyCacheEntry[] = [];
    for (const raw of arr) {
        if (!raw || typeof raw !== "object") continue;
        const p = raw as Partial<DndPolicyWire>;
        if (!p.requestId || !p.objectType || !p.workspaceId || !p.enforcerId || !p.policyMode || !p.expiresAt) {
            continue;
        }
        const scope: "workspace" | "action" =
            p.objectType === "airlock.dnd.action" ? "action" : "workspace";
        parsed.push({
            policy: p as DndPolicyWire,
            scope
        });
    }

    _cache.set(key, { fetchedAt: Date.now(), entries: parsed });
    return parsed;
}

function classifyPolicies(
    entries: DndPolicyCacheEntry[]
) {
    const workspaceDeny: DndPolicyCacheEntry[] = [];
    const workspaceApprove: DndPolicyCacheEntry[] = [];
    const actionDeny: DndPolicyCacheEntry[] = [];
    const actionApprove: DndPolicyCacheEntry[] = [];

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

function findBestActionMatch(
    candidates: DndPolicyCacheEntry[],
    action: DndAction
): DndPolicyCacheEntry | null {
    if (candidates.length === 0) return null;

    const argv = tokenize(action.commandText);
    if (argv.length === 0) return null;

    let best: DndPolicyCacheEntry | null = null;
    let bestPrefixLen = -1;
    let bestCreatedAt = 0;

    for (const e of candidates) {
        const sel = e.policy.actionSelector;
        if (!sel || !sel.argvPrefix || sel.argvPrefix.length === 0) continue;

        // Normalize selector argvPrefix into individual tokens so that both:
        //   ["dotnet","build"] and ["dotnet build"]
        // are treated the same for matching.
        const selectorTokens = sel.argvPrefix
            .flatMap(p => p.split(/\s+/))
            .map(s => s.trim())
            .filter(Boolean);

        const matches = matchesPrefix(argv, selectorTokens);
        if (!matches) continue;

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

function tokenize(cmd: string): string[] {
    return cmd
        .split(/\s+/)
        .map(s => s.trim())
        .filter(Boolean);
}

function matchesPrefix(argv: string[], prefix: string[]): boolean {
    if (argv.length < prefix.length) return false;
    for (let i = 0; i < prefix.length; i++) {
        if (argv[i] !== prefix[i]) return false;
    }
    return true;
}

function pickNewest(entries: DndPolicyCacheEntry[]): DndPolicyCacheEntry | null {
    if (entries.length === 0) return null;
    let best = entries[0];
    let bestCreatedAt = best.policy.createdAt ? Date.parse(best.policy.createdAt) : 0;
    for (let i = 1; i < entries.length; i++) {
        const c = entries[i];
        const createdAtMs = c.policy.createdAt ? Date.parse(c.policy.createdAt) : 0;
        if (createdAtMs > bestCreatedAt) {
            best = c;
            bestCreatedAt = createdAtMs;
        }
    }
    return best;
}

function toResult(
    decision: "approve" | "reject",
    entry: DndPolicyCacheEntry
): DndMatchResult {
    return {
        decision,
        policyId: entry.policy.requestId,
        policyMode: entry.policy.policyMode as DndDecision,
        scope: entry.scope
    };
}

function logMatch(
    decision: "approve" | "reject",
    entry: DndPolicyCacheEntry
): void {
    // Intentionally no logging here to avoid leaking policy identifiers or decisions
}

