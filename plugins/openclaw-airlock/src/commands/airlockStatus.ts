/**
 * Command: airlock-status — Diagnostic slash command.
 *
 * Shows the current Airlock configuration, gateway connectivity,
 * pairing status, and enforcement settings.
 */

import type { AirlockClient } from "../client.js";
import type { AirlockConfig } from "../config.js";
import { loadPairingState } from "../state.js";

/** Command definition for OpenClaw registration. */
export const airlockStatusCommandDef = {
  name: "airlock-status",
  description: "Show Airlock security gateway status and configuration",
};

/**
 * Register the /airlock-status command with the OpenClaw plugin API.
 */
export function registerAirlockStatusCommand(
  api: { registerCommand: (def: unknown, handler: () => Promise<string>) => void },
  client: AirlockClient,
  config: AirlockConfig,
): void {
  api.registerCommand(airlockStatusCommandDef, async () => {
    const health = await client.checkHealth();
    const persistedState = await loadPairingState();

    const lines: string[] = [
      "═══ Airlock Status ═══",
      "",
      `Gateway URL:     ${config.gatewayUrl}`,
      `Connectivity:    ${health.connected ? "✓ Connected" : `✗ Unreachable (${health.error ?? "unknown"})`}`,
      health.serverTime ? `Server Time:     ${health.serverTime}` : "",
      "",
      `Enforcer ID:     ${config.enforcerId}`,
      `Workspace:       ${config.workspaceName}`,
      `Execution Mode:  ${config.executionMode}`,
      `Fail Mode:       ${config.failMode}`,
      `Timeout:         ${config.timeoutMs / 1000}s`,
      `Poll Interval:   ${config.pollIntervalMs}ms`,
      "",
      `Auth (PAT):      ${config.pat ? "✓ Configured" : "✗ Not set"}`,
      `Auth (Client):   ${config.clientId ? `✓ ${config.clientId}` : "✗ Not set"}`,
      "",
      `Pairing:         ${config.routingToken ? "✓ Paired" : "✗ Not paired"}`,
      `Encryption Key:  ${config.encryptionKey ? "✓ Available" : "✗ Not available"}`,
      `State File:      ${persistedState ? `✓ Persisted (${persistedState.pairedAt})` : "✗ No state on disk"}`,
      "",
      `Protected Tools: ${config.protectedTools.length > 0
        ? config.protectedTools.join(", ")
        : "(none — use requestApproval tool for explicit control)"}`,
    ];

    return lines.filter((l) => l !== undefined).join("\n");
  });
}
