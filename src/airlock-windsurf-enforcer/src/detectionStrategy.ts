import * as vscode from "vscode";

/**
 * A pending approval detected by the hooks strategy.
 */
export interface PendingApproval {
    /** Unique ID for deduplication */
    id: string;
    /** What kind of approval is pending */
    type: "agent_step" | "terminal_command";
    /** Text of the button / prompt that was found */
    buttonText: string;
    /** Nearby command text (extracted from hook payload) */
    commandText?: string;
}

/**
 * Configuration passed to the strategy on start.
 */
export interface DetectionConfig {
    autoApprovePatterns: string[];
}

/**
 * Common interface for detection strategies.
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

    /** Event fired when a previously-detected pending approval disappears */
    readonly onPendingCancelled?: vscode.Event<string>;

    /**
     * Execute an approved action.
     * Called by autoMode after Gateway returns ALLOW.
     */
    executeApproval(pending: PendingApproval): Promise<void>;

    /**
     * Execute a rejection action.
     * Called by autoMode after Gateway returns DENY.
     */
    executeRejection(pending: PendingApproval): Promise<void>;
}
