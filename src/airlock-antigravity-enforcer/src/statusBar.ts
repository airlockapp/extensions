import * as vscode from "vscode";

// ── Toggle status bar item (ON/OFF) ──────────────────────────────
export type ToggleState = "off" | "on" | "no-endpoint" | "connected";

export function createToggleStatusBarItem(): vscode.StatusBarItem {
    const item = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right,
        201  // higher priority → appears first (left)
    );
    item.command = "airlock.toggleAutoMode";
    item.text = "$(shield) Airlock";
    item.tooltip = "Airlock Enforcer — click to toggle auto-mode";
    item.show();
    return item;
}

export function updateToggleStatusBar(
    item: vscode.StatusBarItem,
    state: ToggleState
): void {
    switch (state) {
        case "off":
            item.text = "$(shield) Airlock OFF";
            item.tooltip = new vscode.MarkdownString("Airlock: Auto-mode disabled. Click to enable.\n\n[Open Settings](command:airlock.openSettings)");
            (item.tooltip as vscode.MarkdownString).isTrusted = true;
            item.backgroundColor = undefined;
            break;
        case "on":
            item.text = "$(shield) Airlock ON";
            item.tooltip = new vscode.MarkdownString("Airlock: Auto-mode ON. Click to disable.\n\n[Open Settings](command:airlock.openSettings)");
            (item.tooltip as vscode.MarkdownString).isTrusted = true;
            item.backgroundColor = undefined;
            break;
        case "no-endpoint":
            item.text = "$(shield) Airlock ⚠";
            item.tooltip = "Airlock: No endpoint configured";
            item.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
            break;
        case "connected":
            item.text = "$(shield) Airlock";
            item.tooltip = new vscode.MarkdownString("Airlock: Connected. Click to enable auto-mode.\n\n[Open Settings](command:airlock.openSettings)");
            (item.tooltip as vscode.MarkdownString).isTrusted = true;
            item.backgroundColor = undefined;
            break;
    }
}

// ── Approval status bar item (waiting/approved/denied) ───────────
export type ApprovalState = "idle" | "approving" | "allowed" | "denied" | "paused" | "error" | "withdrawn";

export function createApprovalStatusBarItem(): vscode.StatusBarItem {
    const item = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right,
        200  // slightly lower priority → appears after toggle item
    );
    item.command = "airlock.showStatus";
    // Hidden by default — shown only during approval flow
    return item;
}

export function updateApprovalStatusBar(
    item: vscode.StatusBarItem,
    state: ApprovalState
): void {
    switch (state) {
        case "idle":
            item.hide();
            return;
        case "approving":
            item.text = "$(sync~spin) Waiting...";
            item.tooltip = "Airlock: Waiting for mobile approval...";
            item.backgroundColor = undefined;
            break;
        case "allowed":
            item.text = "$(check) Approved";
            item.tooltip = "Airlock: Last action approved";
            item.backgroundColor = undefined;
            break;
        case "denied":
            item.text = "$(x) Denied";
            item.tooltip = "Airlock: Last action denied";
            item.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
            break;
        case "withdrawn":
            item.text = "$(close) Withdrawn";
            item.tooltip = "Airlock: Request withdrawn (manual action taken)";
            item.backgroundColor = undefined;
            break;
        case "paused":
            item.text = "$(debug-pause) Paused";
            item.tooltip = "Airlock: Auto-mode paused (no routing token)";
            item.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
            break;
        case "error":
            item.text = "$(error) Error";
            item.tooltip = "Airlock: Error — check output";
            item.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
            break;
    }
    item.show();
}

// ── Sign-in status bar item (multi-functional: auth + quota warnings) ──
export type SignInState =
    | { status: "not-signed-in" }
    | { status: "signed-in" }
    | { status: "quota-warning"; workspacesUsed: number; workspacesLimit: number };

export function createSignInStatusBarItem(): vscode.StatusBarItem {
    const item = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right,
        97  // lower priority → appears after pairing item
    );
    item.command = "airlock.login";
    item.text = "$(lock) Airlock: Sign In";
    item.tooltip = "Airlock: Click to sign in with your Keycloak account";
    item.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
    return item;
}

export function updateSignInStatusBar(
    item: vscode.StatusBarItem,
    state: SignInState
): void {
    switch (state.status) {
        case "not-signed-in":
            item.command = "airlock.login";
            item.text = "$(lock) Airlock: Sign In";
            item.tooltip = "Airlock: Click to sign in with your Keycloak account";
            item.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
            item.show();
            break;
        case "signed-in":
            item.command = "airlock.openSettings";
            item.text = "$(verified) Signed In";
            item.tooltip = "Airlock: Signed in. Click to open settings.";
            item.backgroundColor = undefined;
            item.show();
            break;
        case "quota-warning":
            item.command = "airlock.openSettings";
            item.text = "$(warning) Quota Warning";
            const quotaDetail = state.workspacesUsed >= 0 && state.workspacesLimit >= 0
                ? `Workspace limit exceeded (${state.workspacesUsed}/${state.workspacesLimit})`
                : `Plan limit reached`;
            item.tooltip = new vscode.MarkdownString(
                `⚠️ **${quotaDetail}**\n\n` +
                `Requests are being allowed (fail-open) but you may need to upgrade your plan or unpair unused workspaces.\n\n` +
                `[Open Settings](command:airlock.openSettings)`
            );
            (item.tooltip as vscode.MarkdownString).isTrusted = true;
            item.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
            item.show();
            break;
    }
}

// ── Backward compat: legacy updateStatusBar still used in some places ──
// Maps old state names to the two new items
export type StatusState =
    | "off"
    | "connecting"
    | "auto-off"
    | "auto-paused"
    | "approving"
    | "allowed"
    | "denied"
    | "error"
    | "no-endpoint"
    | "connected"
    | `auto-on:${string}`;

/** @deprecated Use updateToggleStatusBar + updateApprovalStatusBar instead */
export function updateStatusBar(
    item: vscode.StatusBarItem,
    _state: StatusState
): void {
    // no-op — kept for compile compat during migration
}

/** @deprecated Use createToggleStatusBarItem instead */
export function createStatusBarItem(): vscode.StatusBarItem {
    return createToggleStatusBarItem();
}
