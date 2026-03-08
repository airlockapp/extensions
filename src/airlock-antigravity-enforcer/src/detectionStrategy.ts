import * as vscode from "vscode";

/**
 * A pending approval detected by a strategy.
 */
export interface PendingApproval {
    /** Unique ID for deduplication */
    id: string;
    /** What kind of approval is pending */
    type: "agent_step" | "terminal_command";
    /** Text of the button / prompt that was found */
    buttonText: string;
    /** Nearby command text (CDP only — extracted from <pre>/<code>) */
    commandText?: string;
    /** Conversation tab name (CDP only) */
    tabName?: string;
    /** Page/connection ID for execution (CDP only) */
    pageId?: string;
}

/**
 * Configuration passed to a strategy on start.
 */
export interface DetectionConfig {
    pollIntervalMs: number;
    autoApprovePatterns: string[];
}

/**
 * Common interface for all detection strategies.
 */
export interface DetectionStrategy extends vscode.Disposable {
    readonly name: string;

    /** Check if this strategy can run in the current environment */
    isAvailable(): Promise<boolean>;

    /** Start detection with the given config */
    start(config: DetectionConfig): Promise<void>;

    /** Stop detection */
    stop(): Promise<void>;

    /** Event fired when a pending approval is detected */
    readonly onPendingDetected: vscode.Event<PendingApproval>;

    /** Event fired when a previously-detected pending approval disappears (user acted manually) */
    readonly onPendingCancelled?: vscode.Event<string>;

    /**
     * Execute an approved action (click the button / run the command).
     * Called by autoMode after Gateway returns ALLOW.
     */
    executeApproval(pending: PendingApproval): Promise<void>;

    /**
     * Execute a rejection action (click the reject/cancel/skip button).
     * Called by autoMode after Gateway returns DENY.
     */
    executeRejection(pending: PendingApproval): Promise<void>;
}
