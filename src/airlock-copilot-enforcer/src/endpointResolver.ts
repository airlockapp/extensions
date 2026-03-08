import * as vscode from "vscode";
import * as http from "http";
import * as https from "https";

/** Default gateway for release/prod builds when no local gateway, setting, or env is set */
export const DEFAULT_RELEASE_GATEWAY = "https://gw.airlocks.io";

/** Ports to probe — HTTPS Gateway first, then HTTP Gateway, then legacy HE daemon */
const PROBE_URLS = [
    "https://localhost:7145/echo",
    "http://localhost:5145/echo",
    "https://127.0.0.1:7145/echo",
    "http://127.0.0.1:5145/echo",
    // Legacy HE daemon fallback
    "http://127.0.0.1:7771/healthz",
    "http://127.0.0.1:7772/healthz",
    "http://localhost:7771/healthz",
];

export interface EndpointInfo {
    url: string;
    source: "daemon" | "setting" | "env" | "default";
}

/**
 * Resolve the Airlock approval endpoint.
 * Priority: (1) Local Gateway/HE daemon probe, (2) VS Code setting, (3) Env vars,
 * (4) for release/prod builds only, default to DEFAULT_RELEASE_GATEWAY.
 * Returns null if no endpoint is found (dev builds only).
 */
export async function resolveEndpoint(
    out: vscode.OutputChannel,
    extensionName?: string
): Promise<EndpointInfo | null> {
    out.appendLine("\n[Airlock] Resolving approval endpoint...");

    // (1) Probe local Gateway / HE daemon
    for (const probeUrl of PROBE_URLS) {
        const baseUrl = probeUrl.replace("/echo", "").replace("/healthz", "");
        out.appendLine(`  Probing ${probeUrl}...`);
        try {
            const ok = await probeHealth(probeUrl);
            if (ok) {
                out.appendLine(`  ✓ Gateway found at ${baseUrl}`);
                return { url: baseUrl, source: "daemon" };
            }
        } catch {
            // Probe failed, try next
        }
    }
    out.appendLine("  ✗ No Gateway found on local ports.");

    // (2) VS Code setting
    const settingUrl = vscode.workspace
        .getConfiguration("airlock")
        .get<string>("approvalEndpoint");
    if (settingUrl && settingUrl.trim()) {
        out.appendLine(`  ✓ Using setting: ${settingUrl}`);
        return { url: settingUrl.trim(), source: "setting" };
    }

    // (3) Environment variables
    const envUrl =
        process.env.AIRLOCK_APPROVAL_ENDPOINT || process.env.AIRLOCK_HE_ENDPOINT;
    if (envUrl && envUrl.trim()) {
        out.appendLine(`  ✓ Using env var: ${envUrl}`);
        return { url: envUrl.trim(), source: "env" };
    }

    // (4) Release/prod default: use hosted gateway (dev builds have name ending with -dev)
    if (extensionName && !extensionName.endsWith("-dev")) {
        out.appendLine(`  ✓ Using release default: ${DEFAULT_RELEASE_GATEWAY}`);
        return { url: DEFAULT_RELEASE_GATEWAY, source: "default" };
    }

    out.appendLine("  ⚠ No approval endpoint found.");
    return null;
}

/**
 * HTTP/HTTPS GET probe with 2-second timeout. Returns true if 2xx.
 * Accepts self-signed certificates (Aspire dev cert).
 */
function probeHealth(url: string): Promise<boolean> {
    return new Promise((resolve) => {
        const timeout = setTimeout(() => resolve(false), 2000);
        const parsed = new URL(url);
        const transport = parsed.protocol === "https:" ? https : http;

        const req = transport.get({
            hostname: parsed.hostname,
            port: parsed.port,
            path: parsed.pathname,
            timeout: 2000,
            // Accept Aspire self-signed dev certificate
            rejectUnauthorized: false,
        }, (res) => {
            clearTimeout(timeout);
            resolve(res.statusCode !== undefined && res.statusCode >= 200 && res.statusCode < 300);
            res.resume(); // drain
        });

        req.on("error", () => {
            clearTimeout(timeout);
            resolve(false);
        });
    });
}
