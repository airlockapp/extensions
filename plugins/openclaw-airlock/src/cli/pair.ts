/**
 * CLI: pair — Claim a pre-generated pairing code.
 *
 * Usage: openclaw airlock pair
 *
 * Reads the `pairingCode` from plugin config, claims it against the gateway,
 * derives the shared encryption key via X25519 ECDH, and persists the
 * pairing state to disk (`.airlock/pairing-state.json`).
 */

import type { AirlockClient } from "../client.js";
import type { AirlockConfig } from "../config.js";

/**
 * Register the `airlock pair` CLI command with the OpenClaw plugin API.
 */
export function registerPairCommand(
  api: { registerCliCommand: (def: unknown, handler: (args: unknown) => Promise<void>) => void },
  client: AirlockClient,
  config: AirlockConfig,
): void {
  api.registerCliCommand(
    {
      name: "airlock pair",
      description: "Claim a pre-generated pairing code and establish encrypted communication",
    },
    async () => {
      console.log("Airlock Pairing");
      console.log("═".repeat(40));

      // Check if already paired
      if (config.routingToken && config.encryptionKey) {
        console.log("✓ Already paired.");
        console.log("  To re-pair, clear the existing pairing first.");
        return;
      }

      // Check for pairing code
      if (!config.pairingCode) {
        console.error("✗ No pairing code configured.");
        console.error("  Set 'pairingCode' in your Airlock plugin config.");
        console.error("  Generate a code in the Airlock admin dashboard or mobile app.");
        return;
      }

      // Test gateway connectivity first
      const health = await client.checkHealth();
      if (!health.connected) {
        console.error(`✗ Cannot reach gateway: ${health.error}`);
        console.error("  Fix connectivity before pairing.");
        return;
      }

      console.log(`Gateway:      ${config.gatewayUrl}`);
      console.log(`Enforcer ID:  ${config.enforcerId}`);
      console.log(`Workspace:    ${config.workspaceName}`);
      console.log(`Pairing Code: ${config.pairingCode}`);
      console.log("\nClaiming pairing code (X25519 ECDH key exchange)...");

      try {
        // claimPairing() handles everything:
        // - Generates X25519 keypair
        // - Claims the code with gateway
        // - Polls for completion
        // - Derives shared encryption key
        // - Updates config.routingToken / config.encryptionKey
        // - Persists state to .airlock/pairing-state.json
        const result = await client.claimPairing(config.pairingCode);

        console.log("\n✓ Pairing successful!");
        console.log(`  Routing Token: ${result.routingToken.slice(0, 12)}...`);
        console.log(`  Encryption:    ✓ Key derived (X25519 ECDH + HKDF-SHA256)`);
        console.log(`  State File:    ✓ Persisted to .airlock/pairing-state.json`);
        console.log("\n  Airlock is now ready to enforce approvals.");
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`\n✗ Pairing failed: ${msg}`);

        if (msg.includes("expired")) {
          console.error("  Generate a new pairing code and update your config.");
        }
        if (msg.includes("x25519PublicKey")) {
          console.error("  The pairing response may be missing key exchange data.");
        }
      }
    },
  );
}
