import type { RaygunFixSessionContext } from "@open-inspect/shared";

/**
 * Generate a PR description for a Raygun fix session.
 * 
 * Creates a formatted PR description that includes:
 * - Link to the Raygun issue
 * - Error message and occurrence count
 * - Relevant stack trace excerpt
 * - Agent-generated summary of changes
 * 
 * @param context - Raygun fix session context
 * @param changeSummary - Optional summary of changes made by the agent
 * @returns Formatted PR description in Markdown
 */
export function generateRaygunPRDescription(
  context: RaygunFixSessionContext,
  changeSummary?: string
): string {
  // Truncate stack trace to first 20 lines for PR description
  const stackTraceLines = context.fullStackTrace.split("\n");
  const truncatedStackTrace =
    stackTraceLines.length > 20
      ? stackTraceLines.slice(0, 20).join("\n") + "\n... (truncated)"
      : context.fullStackTrace;

  const description = `## Fixes Raygun Issue

**Issue:** ${context.errorMessage}

**Raygun Link:** ${context.issueUrl}

**Occurrences:** ${context.occurrenceCount}

**Environment:** ${context.environment}

**Version:** ${context.version}

${changeSummary ? `## Changes\n\n${changeSummary}\n` : ""}
## Stack Trace

\`\`\`
${truncatedStackTrace}
\`\`\`

${context.affectedFiles.length > 0 ? `## Affected Files\n\n${context.affectedFiles.map(f => `- ${f}`).join("\n")}\n` : ""}
---
*This PR was created by Open-Inspect AI agent to fix a Raygun error*`;

  return description;
}

/**
 * Generate a PR title for a Raygun fix session.
 * 
 * Creates a concise PR title in the format: "Fix: [error message]"
 * Truncates the error message if it's too long.
 * 
 * @param context - Raygun fix session context
 * @returns Formatted PR title
 */
export function generateRaygunPRTitle(context: RaygunFixSessionContext): string {
  const maxLength = 100;
  const errorMessage = context.errorMessage;

  if (errorMessage.length <= maxLength) {
    return `Fix: ${errorMessage}`;
  }

  // Truncate and add ellipsis
  return `Fix: ${errorMessage.substring(0, maxLength - 3)}...`;
}
