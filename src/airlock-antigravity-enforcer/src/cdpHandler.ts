import * as vscode from "vscode";
import * as http from "http";
import * as path from "path";
import * as fs from "fs";
import { execSync } from "child_process";
import type {
    DetectionStrategy,
    DetectionConfig,
    PendingApproval,
} from "./detectionStrategy.js";

const LOG_PREFIX = "[Airlock CDP]";

interface CDPConnection {
    ws: import("ws").WebSocket;
    injected: boolean;
}

interface CDPPage {
    id: string;
    webSocketDebuggerUrl: string;
    title?: string;
    type?: string;
    url?: string;
}

/**
 * Strategy A: CDP-based detection.
 * Connects to Antigravity's webview via Chrome DevTools Protocol,
 * injects JS to detect accept/reject buttons, and clicks them on approval.
 */
export class CdpDetectionStrategy implements DetectionStrategy {
    readonly name = "cdp";

    private readonly _onPendingDetected = new vscode.EventEmitter<PendingApproval>();
    readonly onPendingDetected = this._onPendingDetected.event;

    private readonly _onPendingCancelled = new vscode.EventEmitter<string>();
    readonly onPendingCancelled = this._onPendingCancelled.event;

    private _connections = new Map<string, CDPConnection>();
    private _messageId = 1;
    private _pendingMessages = new Map<
        number,
        { resolve: (v: unknown) => void; reject: (e: Error) => void }
    >();
    private _pollTimer: ReturnType<typeof setInterval> | null = null;
    private _config: DetectionConfig | null = null;
    private _seenButtons = new Set<string>(); // Dedup within a cycle
    private _lastTargetSignature = ""; // Only log targets when list changes
    private _diagCounter = 0;
    private _ownPort: number | null = null; // Cached: CDP port owned by our VS Code window


    constructor(
        private readonly _out: vscode.OutputChannel,
        private readonly _portStart: number = 9000,
        private readonly _portEnd: number = 9030,
        private readonly _ownPid: number | undefined = undefined,
        private readonly _sessionId: string = "unknown",
        private readonly _workspaceName: string = ""
    ) { }

    // ── Availability ───────────────────────────────────────────────
    async isAvailable(): Promise<boolean> {
        // Retry with backoff — CDP port may not be ready yet at extension activation
        for (let attempt = 1; attempt <= 3; attempt++) {
            const instances = await this._scanForInstances();
            if (instances.length > 0) {
                this._log(`CDP available (attempt ${attempt})`);
                return true;
            }
            this._log(`CDP scan attempt ${attempt}/3: no instances found`);
            if (attempt < 3) {
                await new Promise(r => setTimeout(r, 2000));
            }
        }
        return false;
    }

    /** Update config without restarting (e.g. when autoApprovePatterns change). */
    updateConfig(config: DetectionConfig): void {
        this._config = config;
    }

    // ── Start / Stop ───────────────────────────────────────────────
    async start(config: DetectionConfig): Promise<void> {
        this._seenButtons.clear();
        this._config = config;

        // Detect which CDP port belongs to our VS Code window
        if (!this._ownPort && this._ownPid) {
            this._ownPort = await this._findOwnPort();
        }

        // Connect to any new pages (preserves existing connections)
        try {
            await this._connectAndInject();
        } catch {
            this._log("Initial connect failed — _tick will retry.");
        }

        if (this._pollTimer) { clearInterval(this._pollTimer); }
        this._pollTimer = setInterval(
            () => void this._tick(),
            config.pollIntervalMs
        );
        this._log("Polling started.");
    }

    async stop(): Promise<void> {
        // Only pause the poll timer — keep connections and injected scripts alive
        // so iframe document references (docs=2) survive ON→OFF→ON cycles
        if (this._pollTimer) {
            clearInterval(this._pollTimer);
            this._pollTimer = null;
        }
        this._log("Polling paused (connections preserved).");
    }

    /** Full cleanup — called only on extension deactivation */
    destroy(): void {
        if (this._pollTimer) {
            clearInterval(this._pollTimer);
            this._pollTimer = null;
        }
        for (const [pageId] of this._connections) {
            try {
                void this._evaluate(pageId,
                    'if(typeof window!=="undefined"&&window.__airlockStop) window.__airlockStop()');
            } catch { /* ignore */ }
        }
        this._disconnectAll();
        this._log("Destroyed.");
    }

    // ── Execute approval (click the accept button via CDP) ────────
    async executeApproval(pending: PendingApproval): Promise<void> {
        const pageId = pending.pageId;
        if (!pageId || !this._connections.has(pageId)) {
            this._log(`Cannot execute: page ${pageId} not connected.`);
            return;
        }
        const js = `(function(){
            const id = ${JSON.stringify(pending.id)};
            const btns = document.querySelectorAll('button, [role="button"], a.button');
            for (const b of btns) {
                if (b.dataset.__airlockId === id || b.textContent.trim().toLowerCase() === ${JSON.stringify(pending.buttonText.toLowerCase())}) {
                    b.dispatchEvent(new MouseEvent('click', {view:window,bubbles:true,cancelable:true}));
                    return 'clicked';
                }
            }
            return 'not_found';
        })()`;
        try {
            const result = await this._evaluate(pageId, js);
            this._log(`Click result on ${pageId}: ${JSON.stringify(result)}`);
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            this._log(`Click failed on ${pageId}: ${msg}`);
        }
    }

    // ── Execute rejection (click a reject/cancel/skip button via CDP) ──
    async executeRejection(pending: PendingApproval): Promise<void> {
        const pageId = pending.pageId;
        if (!pageId || !this._connections.has(pageId)) {
            this._log(`Cannot execute rejection: page ${pageId} not connected.`);
            return;
        }
        // Find a visible button near the accept button that matches reject patterns
        const js = `(function(){
            var REJECT = ["reject", "skip", "cancel", "close", "deny", "no", "dismiss", "abort"];
            var btns = document.querySelectorAll('button, [role="button"], a.button');
            for (var i = 0; i < btns.length; i++) {
                var b = btns[i];
                var text = (b.textContent || "").trim().toLowerCase();
                if (text.length === 0 || text.length > 50) continue;
                var style = window.getComputedStyle(b);
                if (style.display === "none" || b.disabled) continue;
                for (var j = 0; j < REJECT.length; j++) {
                    if (text.includes(REJECT[j])) {
                        b.dispatchEvent(new MouseEvent('click', {view:window,bubbles:true,cancelable:true}));
                        return 'clicked:' + text;
                    }
                }
            }
            return 'not_found';
        })()`;
        try {
            const result = await this._evaluate(pageId, js);
            this._log(`Reject click result on ${pageId}: ${JSON.stringify(result)}`);
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            this._log(`Reject click failed on ${pageId}: ${msg}`);
        }
    }

    // ── Internals ──────────────────────────────────────────────────

    private async _tick(): Promise<void> {
        // Reconnect / inject on new pages
        await this._connectAndInject();

        // Run diagnostic every 10 ticks to see what buttons are visible
        this._diagCounter++;
        if (this._diagCounter % 10 === 1) {
            for (const [pageId] of this._connections) {
                try {
                    const diagResult = await this._evaluate(pageId,
                        '(function(){ return typeof window!=="undefined" && window.__airlockDiagnostic ? JSON.stringify(window.__airlockDiagnostic()) : null; })()');
                    const diagRaw = (diagResult as { result?: { value?: string | null } })?.result?.value;
                    if (diagRaw) {
                        const diag = JSON.parse(diagRaw);
                        if (diag.buttonCount > 0) {
                            const acceptBtns = diag.buttons.filter((b: { isAccept: boolean }) => b.isAccept);
                            this._log(`[diag] page=${pageId.substring(0, 8)} docs=${diag.docCount} buttons=${diag.buttonCount} accept=${acceptBtns.length}`);
                            for (const b of diag.buttons.slice(0, 15)) {
                                this._log(`[diag]   ${b.tag} text="${b.text}" inArea=${b.inConvArea} accept=${b.isAccept} vis=${b.visible} cls=${b.classes?.substring(0, 40)}`);
                            }
                        }
                    }
                } catch { /* ignore */ }
                break; // Only diagnose one page per cycle
            }
        }

        const currentButtons = new Set<string>();
        for (const [pageId, conn] of this._connections) {
            try {
                const result = await this._evaluate(pageId,
                    '(function(){ return typeof window!=="undefined" && window.__airlockGetPending ? JSON.stringify(window.__airlockGetPending()) : null; })()');
                const raw = (result as { result?: { value?: string | null } })?.result?.value;

                // Re-inject if the script was lost (page navigated, etc.)
                if (raw === null || raw === undefined) {
                    if (conn.injected) {
                        this._log(`Script lost on ${pageId} — re-injecting...`);
                        conn.injected = false;
                        await this._injectScript(pageId);
                    }
                    continue;
                }

                // Parse the { ownerSession, buttons } response
                const parsed = JSON.parse(raw) as {
                    ownerSession?: string;
                    buttons?: Array<{ id: string; text: string; type: string; commandText?: string }>;
                };

                // Session ownership check: skip pages not owned by this enforcer instance
                const buttons = parsed.buttons ?? (Array.isArray(parsed) ? parsed as Array<{ id: string; text: string; type: string; commandText?: string }> : []);
                if (parsed.ownerSession && parsed.ownerSession !== this._sessionId) {
                    // Page belongs to another enforcer instance — skip silently
                    continue;
                }

                if (buttons.length > 0) {
                    this._log(`[tick] ${buttons.length} button(s) found on ${pageId}: ${buttons.map(b => `"${b.text}"`).join(", ")}`);
                }

                for (const btn of buttons) {
                    currentButtons.add(btn.id);

                    // Only fire for NEW buttons (not seen before)
                    if (this._seenButtons.has(btn.id)) { continue; }
                    this._seenButtons.add(btn.id);

                    // Check auto-approve patterns — matching commands skip Gateway
                    if (btn.commandText && this._isAutoApproved(btn.commandText)) {
                        this._log(`AUTO-APPROVED command near "${btn.text}" — skipping Gateway`);
                        continue;
                    }

                    this._log(`NEW button detected: "${btn.text}" (${btn.type}) id=${btn.id}`);
                    this._onPendingDetected.fire({
                        id: btn.id,
                        type: btn.type === "terminal" ? "terminal_command" : "agent_step",
                        buttonText: btn.text,
                        commandText: btn.commandText,
                        pageId,
                    });
                }
            } catch { /* page may have navigated */ }
        }

        // Remove buttons that are no longer visible (allow re-detection if they come back)
        for (const id of this._seenButtons) {
            if (!currentButtons.has(id)) {
                this._log(`Button disappeared: ${id} — firing cancellation`);
                this._seenButtons.delete(id);
                this._onPendingCancelled.fire(id);
            }
        }
    }

    private _isAutoApproved(commandText: string): boolean {
        const patterns = this._config?.autoApprovePatterns ?? [];
        if (patterns.length === 0) { return false; }
        const lower = commandText.toLowerCase();
        for (const pattern of patterns) {
            const p = pattern.trim();
            if (!p) { continue; }
            try {
                if (p.startsWith("/") && p.lastIndexOf("/") > 0) {
                    const last = p.lastIndexOf("/");
                    const re = new RegExp(p.substring(1, last), p.substring(last + 1) || "i");
                    if (re.test(commandText)) { return true; }
                } else if (lower.includes(p.toLowerCase())) {
                    return true;
                }
            } catch {
                if (lower.includes(p.toLowerCase())) { return true; }
            }
        }
        return false;
    }

    // ── CDP plumbing ───────────────────────────────────────────────

    private async _scanForInstances(): Promise<Array<{ port: number; pages: CDPPage[] }>> {
        const instances: Array<{ port: number; pages: CDPPage[] }> = [];

        // If we know our own port, only scan that one (prevents cross-instance detection)
        if (this._ownPort) {
            try {
                const pages = await this._getPages(this._ownPort);
                if (pages.length > 0) { instances.push({ port: this._ownPort, pages }); }
            } catch { /* port not available — might need re-detection */ }
            return instances;
        }

        // Fallback: scan all ports (no PID info or detection failed)
        for (let port = this._portStart; port <= this._portEnd; port++) {
            try {
                const pages = await this._getPages(port);
                if (pages.length > 0) {
                    this._log(`Found ${pages.length} page(s) on port ${port}`);
                    instances.push({ port, pages });
                }
            } catch { /* port not available */ }
        }
        if (instances.length === 0) {
            this._log(`No CDP instances found in port range ${this._portStart}-${this._portEnd}`);
        }
        return instances;
    }

    /**
     * Detect which CDP port in our range belongs to the current VS Code window.
     * Uses OS-level port-to-PID mapping (netstat on Windows, lsof on macOS/Linux)
     * and matches against ancestor PIDs (the extension host → utility → main Electron chain).
     *
     * Why ancestors? The extension host process tree is:
     *   Main Electron (--remote-debugging-port=XXXX, PID A)
     *     └── Utility/Shared process (PID B)
     *           └── Extension Host (PID C, process.ppid = B)
     * So process.ppid gives us B, but the CDP port listener is A.
     * We walk up the tree to find A.
     */
    private async _findOwnPort(): Promise<number | null> {
        if (!this._ownPid) { return null; }
        this._log(`Detecting own CDP port (starting PID=${this._ownPid})...`);

        try {
            // Collect all ancestor PIDs up to the root Electron process
            const ancestors = this._getAncestorPids(this._ownPid);
            this._log(`Ancestor PID chain: ${ancestors.join(" → ")}`);

            if (process.platform === "win32") {
                return this._findOwnPortWindows(ancestors);
            } else {
                return this._findOwnPortUnix(ancestors);
            }
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            this._log(`Port ownership detection failed: ${msg} — will scan all ports`);
            return null;
        }
    }

    /**
     * Walk up the process tree from startPid, collecting all ancestor PIDs.
     * Stops when a process has no parent, parent is itself, or parent is PID 0/1.
     */
    private _getAncestorPids(startPid: number): number[] {
        const ancestors = [startPid];
        try {
            if (process.platform === "win32") {
                // Get all process parent mappings in one call
                const output = execSync(
                    'wmic process get processid,parentprocessid /format:csv',
                    { encoding: "utf8", timeout: 5000 }
                );
                const pidMap = new Map<number, number>();
                for (const line of output.split("\n")) {
                    const parts = line.trim().split(",");
                    // CSV format: Node,ParentProcessId,ProcessId
                    if (parts.length >= 3) {
                        const parent = parseInt(parts[1], 10);
                        const pid = parseInt(parts[2], 10);
                        if (!isNaN(parent) && !isNaN(pid)) {
                            pidMap.set(pid, parent);
                        }
                    }
                }
                let current = startPid;
                for (let i = 0; i < 10; i++) { // max 10 levels
                    const parent = pidMap.get(current);
                    if (!parent || parent === current || parent <= 1) { break; }
                    ancestors.push(parent);
                    current = parent;
                }
            } else {
                // Unix: ps -o ppid= -p PID
                let current = startPid;
                for (let i = 0; i < 10; i++) {
                    try {
                        const output = execSync(
                            `ps -o ppid= -p ${current}`,
                            { encoding: "utf8", timeout: 2000 }
                        ).trim();
                        const parent = parseInt(output, 10);
                        if (isNaN(parent) || parent === current || parent <= 1) { break; }
                        ancestors.push(parent);
                        current = parent;
                    } catch { break; }
                }
            }
        } catch (err: unknown) {
            this._log(`Process tree walk failed: ${err instanceof Error ? err.message : String(err)}`);
        }
        return ancestors;
    }

    private _findOwnPortWindows(ancestorPids: number[]): number | null {
        const ancestorSet = new Set(ancestorPids);
        // netstat -anop tcp returns lines like:
        //   TCP    127.0.0.1:9000    0.0.0.0:0    LISTENING    12345
        const output = execSync("netstat -anop tcp", { encoding: "utf8", timeout: 5000 });
        for (let port = this._portStart; port <= this._portEnd; port++) {
            // Match lines containing our port in LISTENING state
            const pattern = new RegExp(
                `\\s127\\.0\\.0\\.1:${port}\\s+\\S+\\s+LISTENING\\s+(\\d+)`,
                "m"
            );
            const match = output.match(pattern);
            if (match) {
                const listenerPid = parseInt(match[1], 10);
                if (ancestorSet.has(listenerPid)) {
                    this._log(`✓ Own port detected: ${port} (PID=${listenerPid} is ancestor of extension host)`);
                    return port;
                } else {
                    this._log(`  Port ${port} owned by PID=${listenerPid} (not in our ancestor chain)`);
                }
            }
        }
        this._log(`No port in range ${this._portStart}-${this._portEnd} matched ancestor PIDs: ${ancestorPids.join(", ")}`);
        return null;
    }

    private _findOwnPortUnix(ancestorPids: number[]): number | null {
        const ancestorSet = new Set(ancestorPids);
        // lsof -iTCP:PORT -sTCP:LISTEN -t returns just the PID
        for (let port = this._portStart; port <= this._portEnd; port++) {
            try {
                const output = execSync(
                    `lsof -iTCP:${port} -sTCP:LISTEN -t`,
                    { encoding: "utf8", timeout: 3000 }
                ).trim();
                if (!output) { continue; }
                const listenerPid = parseInt(output.split("\n")[0], 10);
                if (ancestorSet.has(listenerPid)) {
                    this._log(`✓ Own port detected: ${port} (PID=${listenerPid} is ancestor of extension host)`);
                    return port;
                } else {
                    this._log(`  Port ${port} owned by PID=${listenerPid} (not in our ancestor chain)`);
                }
            } catch { /* port not listening */ }
        }
        this._log(`No port in range ${this._portStart}-${this._portEnd} matched ancestor PIDs: ${ancestorPids.join(", ")}`);
        return null;
    }

    private _getPages(port: number): Promise<CDPPage[]> {
        return new Promise((resolve, reject) => {
            const req = http.get(
                { hostname: "127.0.0.1", port, path: "/json/list", timeout: 2000 },
                (res) => {
                    let data = "";
                    res.on("data", (chunk) => (data += chunk));
                    res.on("end", () => {
                        try {
                            const parsed = JSON.parse(data) as CDPPage[];
                            // Only keep evaluatable page types with WS URLs
                            let evaluatable = parsed.filter((p) => {
                                if (!p.webSocketDebuggerUrl) return false;
                                const t = (p.type ?? "").toLowerCase();
                                return !t || t === "page" || t === "iframe" || t === "webview";
                            });
                            // Filter by workspace name to avoid cross-instance leaks
                            if (this._workspaceName) {
                                const wsName = this._workspaceName.toLowerCase();
                                const owned = evaluatable.filter(p => {
                                    const title = (p.title ?? "").toLowerCase();
                                    return title.includes(wsName);
                                });
                                if (owned.length > 0) {
                                    evaluatable = owned;
                                }
                                // If no match, fall back to all evaluatable (safeguard)
                            }
                            // Only log when target list changes
                            const sig = parsed.map(p => `${p.type}:${p.id}`).sort().join(",");
                            if (sig !== this._lastTargetSignature) {
                                this._lastTargetSignature = sig;
                                for (const p of parsed) {
                                    this._log(`  Target: type=${p.type ?? "?"} title="${p.title ?? "?"}" ws=${p.webSocketDebuggerUrl ? "yes" : "no"}`);
                                }
                                this._log(`  Workspace filter: "${this._workspaceName}" → ${evaluatable.length} owned / ${parsed.length} total on port ${port}`);
                            }
                            resolve(evaluatable);
                        } catch (e) {
                            reject(e);
                        }
                    });
                }
            );
            req.on("error", reject);
            req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
        });
    }

    private async _connectAndInject(): Promise<void> {
        const instances = await this._scanForInstances();
        for (const instance of instances) {
            for (const page of instance.pages) {
                if (!this._connections.has(page.id)) {
                    await this._connectToPage(page);
                    // Enable Runtime domain — required before evaluate on many targets
                    const conn = this._connections.get(page.id);
                    if (conn) {
                        try {
                            await this._sendCommand(page.id, "Runtime.enable", {}, 5000);
                            this._log(`Runtime.enable OK on ${page.id}`);
                        } catch {
                            this._log(`Runtime.enable failed on ${page.id} — may still work`);
                        }
                    }
                }
                const conn = this._connections.get(page.id);
                if (conn && !conn.injected) {
                    await this._injectScript(page.id);
                }
            }
        }
    }

    private async _connectToPage(page: CDPPage): Promise<void> {
        // Dynamic import for ws (bundled as dependency)
        const { WebSocket } = await import("ws");
        return new Promise((resolve) => {
            const ws = new WebSocket(page.webSocketDebuggerUrl);
            ws.on("open", () => {
                this._connections.set(page.id, { ws, injected: false });
                this._log(`Connected to page ${page.id} (type=${page.type ?? "?"}, title="${page.title ?? "?"}")`);
                resolve();
            });
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            ws.on("message", (data: any, isBinary: boolean) => {
                try {
                    // ws can deliver Buffer, Buffer[], or string
                    let text: string;
                    if (typeof data === "string") {
                        text = data;
                    } else if (Buffer.isBuffer(data)) {
                        text = data.toString("utf8");
                    } else if (Array.isArray(data)) {
                        text = Buffer.concat(data).toString("utf8");
                    } else {
                        text = String(data);
                    }
                    const msg = JSON.parse(text) as {
                        id?: number;
                        result?: unknown;
                        error?: { message: string };
                        method?: string;
                    };

                    // CDP events (no id) — ignore
                    if (!msg.id) { return; }

                    if (this._pendingMessages.has(msg.id)) {
                        const handler = this._pendingMessages.get(msg.id)!;
                        this._pendingMessages.delete(msg.id);
                        if (msg.error) {
                            this._log(`CDP error for msg ${msg.id}: ${msg.error.message}`);
                            handler.reject(new Error(msg.error.message));
                        } else {
                            handler.resolve(msg.result);
                        }
                    }
                } catch (parseErr) {
                    this._log(`Message parse error: ${parseErr}`);
                }
            });
            ws.on("error", (err) => {
                this._log(`WS error on ${page.id}: ${err instanceof Error ? err.message : err}`);
                this._connections.delete(page.id);
                resolve();
            });
            ws.on("close", () => {
                this._log(`WS closed on ${page.id}`);
                this._connections.delete(page.id);
            });
        });
    }

    private async _injectScript(pageId: string): Promise<void> {
        // Step 1: Probe — verify the WS roundtrip works at all
        try {
            this._log(`Probing page ${pageId}...`);
            const probeResult = await this._sendCommand(pageId, "Runtime.evaluate", {
                expression: "1+1",
                returnByValue: true,
            }, 5000);
            this._log(`Probe OK on ${pageId}: ${JSON.stringify(probeResult)}`);
        } catch (probeErr: unknown) {
            const msg = probeErr instanceof Error ? probeErr.message : String(probeErr);
            this._log(`Probe FAILED on ${pageId}: ${msg} — skipping injection`);
            // Remove dead connection
            const conn = this._connections.get(pageId);
            if (conn) { try { conn.ws.close(); } catch { /* */ } }
            this._connections.delete(pageId);
            return;
        }

        // Step 2: Load the script and stamp with our session ID
        const scriptPath = path.join(__dirname, "cdpScript.js");
        let script: string;
        try {
            script = fs.readFileSync(scriptPath, "utf8");
        } catch {
            this._log("cdpScript.js not found — using inline fallback.");
            script = getCdpScriptFallback();
        }
        // Replace the placeholder with our actual session ID
        script = script.replace("__AIRLOCK_SESSION_ID__", this._sessionId);

        // Step 3: Inject with retry
        for (let attempt = 1; attempt <= 2; attempt++) {
            try {
                this._log(`Injection attempt ${attempt} on ${pageId} (${script.length} chars)...`);
                const result = await this._sendCommand(pageId, "Runtime.evaluate", {
                    expression: script,
                    userGesture: true,
                    awaitPromise: false,
                    returnByValue: true,
                }, 15000) as { exceptionDetails?: { text: string } };

                if (result.exceptionDetails) {
                    this._log(`Injection error on ${pageId}: ${result.exceptionDetails.text}`);
                } else {
                    const conn = this._connections.get(pageId);
                    if (conn) { conn.injected = true; }
                    this._log(`✓ Injected script into ${pageId}`);
                }
                return; // Success or exception — don't retry
            } catch (err: unknown) {
                const msg = err instanceof Error ? err.message : String(err);
                this._log(`Injection attempt ${attempt} failed on ${pageId}: ${msg}`);
                if (attempt < 2) {
                    // Brief pause before retry
                    await new Promise(r => setTimeout(r, 1000));
                }
            }
        }
    }

    private _evaluate(pageId: string, expression: string): Promise<unknown> {
        return this._sendCommand(pageId, "Runtime.evaluate", {
            expression,
            returnByValue: true,
        });
    }

    private _sendCommand(
        pageId: string,
        method: string,
        params: Record<string, unknown> = {},
        timeoutMs: number = 5000
    ): Promise<unknown> {
        const conn = this._connections.get(pageId);
        if (!conn || conn.ws.readyState !== 1 /* OPEN */) {
            return Promise.reject(new Error("connection dead"));
        }
        const id = this._messageId++;
        return new Promise((resolve, reject) => {
            this._pendingMessages.set(id, { resolve, reject });
            conn.ws.send(JSON.stringify({ id, method, params }));
            setTimeout(() => {
                if (this._pendingMessages.has(id)) {
                    this._pendingMessages.delete(id);
                    reject(new Error("timeout"));
                }
            }, timeoutMs);
        });
    }

    private _disconnectAll(): void {
        for (const [, conn] of this._connections) {
            try { conn.ws.close(); } catch { /* ignore */ }
        }
        this._connections.clear();
    }

    getConnectionCount(): number {
        return this._connections.size;
    }

    private _log(msg: string): void {
        this._out.appendLine(`${LOG_PREFIX} ${msg}`);
    }

    dispose(): void {
        this.destroy();
        this._onPendingDetected.dispose();
        this._onPendingCancelled.dispose();
    }
}

/**
 * Minimal inline fallback if cdpScript.js is not found on disk.
 */
function getCdpScriptFallback(): string {
    return `(function(){
        if(typeof window==="undefined") return;
        window.__airlockGetPending = function() { return []; };
        window.__airlockStop = function() {};
    })()`;
}
