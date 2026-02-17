/**
 * Build Slack Block Kit messages for completion notifications.
 */

import type { AgentResponse, CallbackContext } from "../types";

/**
 * Slack Block Kit block type (subset).
 */
interface SlackBlock {
  type: string;
  text?: { type: string; text: string };
  elements?: Array<{ type: string; text?: unknown; url?: string; action_id?: string }>;
}

/**
 * Status emoji constants.
 */
const STATUS_EMOJI = {
  success: ":white_check_mark:",
  warning: ":warning:",
} as const;

/**
 * Truncation limits.
 */
const TRUNCATE_LIMIT = 2000;
const FALLBACK_TEXT_LIMIT = 150;

/**
 * Build Slack blocks for completion message.
 */
export function buildCompletionBlocks(
  sessionId: string,
  response: AgentResponse,
  context: CallbackContext,
  webAppUrl: string
): SlackBlock[] {
  const blocks: SlackBlock[] = [];

  // 1. Response text (truncated)
  const text = truncateForSlack(response.textContent, TRUNCATE_LIMIT);
  blocks.push({
    type: "section",
    text: { type: "mrkdwn", text: text || "_Agent completed._" },
  });

  // 2. Artifacts (PRs, branches)
  if (response.artifacts.length > 0) {
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: "*Created:*\n" + response.artifacts.map((a) => `- <${a.url}|${a.label}>`).join("\n"),
      },
    });
  }

  // 3. Key tool actions
  const keyToolNames = ["Edit", "Write", "Bash"] as const;
  const keyTools = response.toolCalls
    .filter((t) => keyToolNames.includes(t.tool as (typeof keyToolNames)[number]))
    .slice(0, 5);
  if (keyTools.length > 0) {
    blocks.push({
      type: "context",
      elements: [{ type: "mrkdwn", text: keyTools.map((t) => t.summary).join(" | ") }],
    });
  }

  // 4. Status footer
  const emoji = response.success ? STATUS_EMOJI.success : STATUS_EMOJI.warning;
  const status = response.success ? "Done" : "Completed with issues";
  blocks.push({
    type: "context",
    elements: [
      {
        type: "mrkdwn",
        text: `${emoji} ${status}  |  ${context.model}  |  ${context.repoFullName}`,
      },
    ],
  });

  // 5. View Session button
  blocks.push({
    type: "actions",
    elements: [
      {
        type: "button",
        text: { type: "plain_text", text: "View Session" },
        url: `${webAppUrl}/session/${sessionId}`,
        action_id: "view_session",
      },
    ],
  });

  return blocks;
}

/**
 * Get truncated text for Slack's fallback text field.
 */
export function getFallbackText(response: AgentResponse): string {
  return response.textContent.slice(0, FALLBACK_TEXT_LIMIT) || "Agent completed.";
}

/**
 * Truncate text for Slack display with smart sentence breaks.
 */
function truncateForSlack(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  const truncated = text.slice(0, maxLen);
  const lastPeriod = truncated.lastIndexOf(". ");
  if (lastPeriod > maxLen * 0.7) {
    return truncated.slice(0, lastPeriod + 1) + "\n\n_...truncated_";
  }
  return truncated + "...\n\n_...truncated_";
}
