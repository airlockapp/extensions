/**
 * Hook: beforeTool — automatic interception of protected tool executions.
 *
 * Intercepts tool calls before they execute and requires approval from
 * the mobile approver for tools listed in `protectedTools`.
 *
 * If `protectedTools` is empty, no tools are automatically protected
 * (opt-in model). Use the requestApproval tool for explicit control.
 *
 * Checks DND (Do Not Disturb) policies before requesting approval —
 * if a matching DND policy is active, the tool is auto-approved.
 */

import type { AirlockClient } from "../client.js";
import type { AirlockConfig } from "../config.js";

/** Context passed to the beforeTool hook by OpenClaw. */
export interface BeforeToolContext {
  /** The name of the tool being executed. */
  toolName: string;
  /** The tool's input arguments. */
  toolInput: unknown;
  /** Optional metadata about the tool call. */
  metadata?: Record<string, unknown>;
}

/**
 * Register the beforeTool hook with the OpenClaw plugin API.
 *
 * The hook checks if the tool being executed is in the `protectedTools` list.
 * If it is, an approval request is sent to the gateway and the hook blocks
 * until the approver decides.
 *
 * @param api OpenClaw plugin API (api.registerHook)
 * @param client AirlockClient instance
 * @param config Validated AirlockConfig
 */
export function registerBeforeToolHook(
  api: { registerHook: (event: string, handler: (context: unknown) => Promise<void>) => void },
  client: AirlockClient,
  config: AirlockConfig,
): void {
  api.registerHook("beforeTool", async (rawContext: unknown) => {
    const context = rawContext as BeforeToolContext;
    const toolName = context.toolName;

    // ── Opt-in model: if protectedTools is empty, do nothing ──
    if (config.protectedTools.length === 0) {
      return;
    }

    // ── Check if this tool is in the protected list ──
    const isProtected = config.protectedTools.some(
      (pattern) => matchToolName(toolName, pattern),
    );

    if (!isProtected) {
      return; // Not protected — allow without approval
    }

    // ── Check DND (Do Not Disturb) policies ──
    // If a matching DND policy is active, auto-approve without bothering the user
    const dndActive = await client.isDndActive();
    if (dndActive) {
      return; // DND active — auto-approve silently
    }

    // ── Build a readable command text from tool input ──
    let commandText: string;
    try {
      commandText = typeof context.toolInput === "string"
        ? context.toolInput
        : JSON.stringify(context.toolInput, null, 2);
    } catch {
      commandText = String(context.toolInput);
    }

    // Truncate very long inputs to avoid overwhelming the approver
    const maxLen = 2000;
    if (commandText.length > maxLen) {
      commandText = commandText.slice(0, maxLen) + "\n... (truncated)";
    }

    // ── Request approval ──
    const decision = await client.requestApproval({
      actionType: toolName,
      commandText,
      description: `Tool: ${toolName}`,
    });

    // ── Apply decision ──
    if (decision.decision === "approved") {
      return; // Allow tool execution
    }

    if (decision.decision === "rejected") {
      throw new Error(
        `Airlock: Action denied by approver — ${decision.reason ?? "no reason provided"}. ` +
        `Do NOT retry this action automatically.`,
      );
    }

    // Timeout — apply failMode
    if (config.failMode === "closed") {
      throw new Error(
        "Airlock: Approval timed out — blocking (fail-closed). " +
        "Do NOT retry this action automatically.",
      );
    }

    // failMode === "open" — allow silently
    return;
  });
}

/**
 * Match a tool name against a pattern.
 * Supports exact match and glob-like wildcards (*).
 */
function matchToolName(toolName: string, pattern: string): boolean {
  // Exact match
  if (toolName === pattern) return true;

  // Simple wildcard: "shell.*" matches "shell.exec", "shell.run", etc.
  if (pattern.includes("*")) {
    const regex = new RegExp(
      "^" + pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$",
    );
    return regex.test(toolName);
  }

  // Case-insensitive match
  if (toolName.toLowerCase() === pattern.toLowerCase()) return true;

  return false;
}
