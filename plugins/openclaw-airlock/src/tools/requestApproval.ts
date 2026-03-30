/**
 * Tool: requestApproval — AI-callable tool for explicit approval requests.
 *
 * The agent calls this tool when it wants to get approval for an action
 * before executing it. Unlike the beforeTool hook (which intercepts
 * automatically), this tool gives the agent explicit control.
 *
 * Respects DND (Do Not Disturb) policies — if DND is active, auto-approves.
 */

import type { AirlockClient, Decision } from "../client.js";
import type { AirlockConfig } from "../config.js";

/** Input schema for the requestApproval tool. */
export interface RequestApprovalInput {
  /** The action requiring approval (e.g. "deploy to production"). */
  action: string;
  /** Why this action needs approval. */
  reason: string;
  /** Additional context about the action. */
  context?: string;
}

/** Output schema for the requestApproval tool. */
export interface RequestApprovalOutput {
  /** The decision: "approved", "rejected", or "timeout". */
  decision: "approved" | "rejected" | "timeout";
  /** The exchange request ID (for follow-up status checks). */
  requestId: string;
  /** Optional message from the approver or system. */
  message?: string;
}

/** Tool definition for OpenClaw registration. */
export const requestApprovalToolDef = {
  name: "airlock_request_approval",
  description:
    "Request human approval for an action via Airlock. " +
    "Use this before executing high-risk operations like deployments, " +
    "data mutations, or system configuration changes. " +
    "The request will be sent to the mobile approver app.",
  inputSchema: {
    type: "object" as const,
    required: ["action", "reason"] as const,
    properties: {
      action: {
        type: "string" as const,
        description: "The action requiring approval (e.g. 'deploy to production', 'delete database')",
      },
      reason: {
        type: "string" as const,
        description: "Why this action needs approval",
      },
      context: {
        type: "string" as const,
        description: "Additional context about the action (optional)",
      },
    },
  },
};

/**
 * Register the requestApproval tool with the OpenClaw plugin API.
 *
 * @param api OpenClaw plugin API (api.registerTool)
 * @param client AirlockClient instance
 * @param config Validated AirlockConfig
 */
export function registerRequestApprovalTool(
  api: { registerTool: (def: unknown, handler: (input: unknown) => Promise<unknown>) => void },
  client: AirlockClient,
  config: AirlockConfig,
): void {
  api.registerTool(requestApprovalToolDef, async (rawInput: unknown) => {
    const input = rawInput as RequestApprovalInput;

    // Check DND (Do Not Disturb) policies before sending approval request
    const dndActive = await client.isDndActive();
    if (dndActive) {
      return {
        decision: "approved",
        requestId: "",
        message: "Auto-approved — Do Not Disturb mode is active.",
      } satisfies RequestApprovalOutput;
    }

    const result: Decision = await client.requestApproval({
      actionType: input.action,
      commandText: input.reason,
      description: `Approval requested: ${input.action}`,
      context: input.context,
    });

    const output: RequestApprovalOutput = {
      decision: result.decision,
      requestId: result.requestId,
    };

    // Build a meaningful message
    if (result.decision === "approved") {
      output.message = "Action approved by the human approver. Proceed.";
    } else if (result.decision === "rejected") {
      output.message = result.reason ?? "Action rejected by the approver.";
    } else {
      // timeout
      if (config.failMode === "open") {
        output.message = "Approval timed out. Proceeding (fail-open mode).";
        output.decision = "approved"; // Override to approved in fail-open
      } else {
        output.message = "Approval timed out. Action blocked (fail-closed mode).";
      }
    }

    return output;
  });
}
