/**
 * CLI: setup — Validate config and test gateway connectivity.
 *
 * Usage: openclaw airlock setup
 */

import type { AirlockClient } from "../client.js";
import type { AirlockConfig } from "../config.js";

/**
 * Register the `airlock setup` CLI command with the OpenClaw plugin API.
 */
export function registerSetupCommand(
  api: { registerCliCommand: (def: unknown, handler: (args: unknown) => Promise<void>) => void },
  client: AirlockClient,
  config: AirlockConfig,
): void {
  api.registerCliCommand(
    {
      name: "airlock setup",
      description: "Validate Airlock configuration and test gateway connectivity",
    },
    async () => {
      console.log("Airlock Setup");
      console.log("═".repeat(40));

      // 1. Config summary
      console.log(`\nGateway URL:    ${config.gatewayUrl}`);
      console.log(`Enforcer ID:   ${config.enforcerId}`);
      console.log(`Workspace:     ${config.workspaceName}`);
      console.log(`Fail Mode:     ${config.failMode}`);
      console.log(`Auth (PAT):    ${config.pat ? "✓" : "✗"}`);
      console.log(`Auth (Client): ${config.clientId ? "✓" : "✗"}`);

      // 2. Gateway connectivity
      console.log("\nTesting gateway connectivity...");
      const health = await client.checkHealth();
      if (health.connected) {
        console.log(`✓ Connected to ${health.gatewayUrl}`);
        if (health.serverTime) {
          console.log(`  Server time: ${health.serverTime}`);
        }
      } else {
        console.error(`✗ Cannot reach gateway: ${health.error}`);
        console.error("  Check the gatewayUrl in your plugin config.");
        return;
      }

      // 3. Pairing status
      if (config.routingToken && config.encryptionKey) {
        console.log("\n✓ Paired — ready to enforce");
      } else if (config.pairingCode) {
        console.log("\n⚠ Not paired — run 'airlock pair' to claim your pairing code");
      } else {
        console.log("\n⚠ Not paired — configure a pairingCode and run 'airlock pair'");
      }

      // 4. Protected tools
      if (config.protectedTools.length > 0) {
        console.log(`\nProtected tools (${config.protectedTools.length}):`);
        for (const tool of config.protectedTools) {
          console.log(`  • ${tool}`);
        }
      } else {
        console.log("\nNo tools protected via hook (opt-in model).");
        console.log("Use the airlock_request_approval tool for explicit approval.");
      }

      console.log("\n✓ Setup complete");
    },
  );
}
