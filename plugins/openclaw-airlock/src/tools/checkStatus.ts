/**
 * Tool: checkStatus — AI-callable tool to check an existing exchange status.
 *
 * The agent can use this to follow up on a previously submitted approval
 * request and check whether a decision has been made.
 */

import { AirlockGatewayError } from "@airlockapp/gateway-sdk";
import type { AirlockClient } from "../client.js";
import type { AirlockConfig } from "../config.js";

/** Input schema for the checkStatus tool. */
export interface CheckStatusInput {
  /** The exchange request ID from a previous approval request. */
  requestId: string;
}

/** Output schema for the checkStatus tool. */
export interface CheckStatusOutput {
  /** The exchange state (e.g. "Pending", "Decided", "Expired", "Withdrawn"). */
  state: string;
  /** Human-readable message. */
  message: string;
}

/** Tool definition for OpenClaw registration. */
export const checkStatusToolDef = {
  name: "airlock_check_status",
  description:
    "Check the status of a previously submitted Airlock approval request. " +
    "Use the requestId returned from airlock_request_approval.",
  inputSchema: {
    type: "object" as const,
    required: ["requestId"] as const,
    properties: {
      requestId: {
        type: "string" as const,
        description: "The exchange request ID from a previous approval request",
      },
    },
  },
};

/**
 * Register the checkStatus tool with the OpenClaw plugin API.
 */
export function registerCheckStatusTool(
  api: { registerTool: (def: unknown, handler: (input: unknown) => Promise<unknown>) => void },
  client: AirlockClient,
  _config: AirlockConfig,
): void {
  api.registerTool(checkStatusToolDef, async (rawInput: unknown) => {
    const input = rawInput as CheckStatusInput;

    if (!input.requestId?.trim()) {
      return {
        state: "error",
        message: "requestId is required",
      } satisfies CheckStatusOutput;
    }

    try {
      const status = await client.getExchangeStatus(input.requestId);

      let message = `Exchange ${input.requestId}: ${status.state}`;

      if (status.state === "Decided") {
        message += " — a decision has been made.";
      } else if (status.state === "Pending") {
        message += " — waiting for approver response.";
      } else if (status.state === "Expired") {
        message += " — the request has expired.";
      } else if (status.state === "Withdrawn") {
        message += " — the request was withdrawn.";
      }

      return { state: status.state, message } satisfies CheckStatusOutput;
    } catch (err) {
      if (err instanceof AirlockGatewayError && err.statusCode === 404) {
        return {
          state: "not_found",
          message: `Exchange ${input.requestId} not found. It may have expired or been withdrawn.`,
        } satisfies CheckStatusOutput;
      }

      return {
        state: "error",
        message: `Failed to check status: ${err instanceof Error ? err.message : String(err)}`,
      } satisfies CheckStatusOutput;
    }
  });
}
