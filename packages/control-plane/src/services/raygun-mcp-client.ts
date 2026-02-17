import { createLogger } from "../logger";
import type { RaygunIssue, RaygunIssueDetail } from "@open-inspect/shared";

const log = createLogger("raygun-mcp-client");

/**
 * Client for communicating with the Raygun MCP server.
 * 
 * This client handles communication with the Raygun MCP server running in Modal sandboxes,
 * parsing and transforming MCP responses to typed RaygunIssue/RaygunIssueDetail objects.
 */
export class RaygunMCPClient {
  constructor(private readonly mcpServerUrl: string) {}

  /**
   * List open issues for a Raygun application.
   * 
   * @param applicationId - Raygun Application ID
   * @returns Array of RaygunIssue objects
   * @throws Error if MCP server communication fails or returns invalid data
   */
  async listIssues(applicationId: string): Promise<RaygunIssue[]> {
    try {
      const response = await fetch(`${this.mcpServerUrl}/issues`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          applicationId,
        }),
      });

      if (!response.ok) {
        const status = response.status;
        const text = await response.text();
        
        if (status === 401 || status === 403) {
          throw new Error("Authentication failed. Please check your Raygun Application ID configuration.");
        }
        
        if (status === 429) {
          throw new Error("Raygun rate limit exceeded. Please try again in a few minutes.");
        }
        
        log.error("Failed to list Raygun issues", {
          status,
          response_text: text,
          application_id_length: applicationId.length,
        });
        throw new Error(`Failed to fetch issues from Raygun: ${status}`);
      }

      const data = await response.json();
      
      // Transform MCP response to RaygunIssue array
      if (!Array.isArray(data.issues)) {
        throw new Error("Invalid response format from Raygun MCP server");
      }

      return data.issues.map((issue: any) => ({
        id: issue.id,
        errorMessage: issue.errorMessage || issue.message || "",
        stackTracePreview: issue.stackTracePreview || issue.stackTrace?.substring(0, 200) || "",
        occurrenceCount: issue.occurrenceCount || issue.count || 0,
        firstSeenAt: new Date(issue.firstSeenAt || issue.firstOccurredOn),
        lastSeenAt: new Date(issue.lastSeenAt || issue.lastOccurredOn),
        status: issue.status || "active",
        affectedUsers: issue.affectedUsers || issue.usersAffected || 0,
      }));
    } catch (e) {
      if (e instanceof Error) {
        throw e;
      }
      log.error("Unexpected error listing Raygun issues", {
        error: String(e),
      });
      throw new Error("Unable to connect to Raygun. Please try again later.");
    }
  }

  /**
   * Get detailed information about a specific Raygun issue.
   * 
   * @param applicationId - Raygun Application ID
   * @param issueId - Raygun Issue ID
   * @returns RaygunIssueDetail object with full crash information
   * @throws Error if issue not found or MCP server communication fails
   */
  async getIssueDetail(applicationId: string, issueId: string): Promise<RaygunIssueDetail> {
    try {
      const response = await fetch(`${this.mcpServerUrl}/issues/${issueId}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          applicationId,
        }),
      });

      if (!response.ok) {
        const status = response.status;
        const text = await response.text();
        
        if (status === 404) {
          throw new Error("Issue not found. It may have been resolved or deleted.");
        }
        
        if (status === 401 || status === 403) {
          throw new Error("Authentication failed. Please check your Raygun Application ID configuration.");
        }
        
        if (status === 429) {
          throw new Error("Raygun rate limit exceeded. Please try again in a few minutes.");
        }
        
        log.error("Failed to get Raygun issue detail", {
          status,
          response_text: text,
          issue_id: issueId,
        });
        throw new Error(`Failed to fetch issue details from Raygun: ${status}`);
      }

      const data = await response.json();
      const issue = data.issue;
      
      if (!issue) {
        throw new Error("Invalid response format from Raygun MCP server");
      }

      // Transform MCP response to RaygunIssueDetail
      return {
        id: issue.id,
        errorMessage: issue.errorMessage || issue.message || "",
        stackTracePreview: issue.stackTracePreview || issue.stackTrace?.substring(0, 200) || "",
        occurrenceCount: issue.occurrenceCount || issue.count || 0,
        firstSeenAt: new Date(issue.firstSeenAt || issue.firstOccurredOn),
        lastSeenAt: new Date(issue.lastSeenAt || issue.lastOccurredOn),
        status: issue.status || "active",
        affectedUsers: issue.affectedUsers || issue.usersAffected || 0,
        fullStackTrace: issue.fullStackTrace || issue.stackTrace || "",
        affectedFiles: issue.affectedFiles || this.extractFilesFromStackTrace(issue.stackTrace || ""),
        context: {
          environment: issue.context?.environment || issue.environment || "unknown",
          version: issue.context?.version || issue.version || "unknown",
          customData: issue.context?.customData || issue.customData || {},
        },
        recentOccurrences: (issue.recentOccurrences || []).map((occurrence: any) => ({
          timestamp: new Date(occurrence.timestamp || occurrence.occurredOn),
          stackTrace: occurrence.stackTrace || "",
          context: occurrence.context || {},
        })),
      };
    } catch (e) {
      if (e instanceof Error) {
        throw e;
      }
      log.error("Unexpected error getting Raygun issue detail", {
        error: String(e),
        issue_id: issueId,
      });
      throw new Error("Unable to connect to Raygun. Please try again later.");
    }
  }

  /**
   * Extract file paths from a stack trace string.
   * 
   * @param stackTrace - Stack trace string
   * @returns Array of unique file paths found in the stack trace
   */
  private extractFilesFromStackTrace(stackTrace: string): string[] {
    const filePattern = /(?:at\s+.*?\s+\()?([a-zA-Z]:[\\\/].*?|\/.*?|\.\/.*?):(\d+):(\d+)/g;
    const files = new Set<string>();
    
    let match;
    while ((match = filePattern.exec(stackTrace)) !== null) {
      if (match[1]) {
        files.add(match[1]);
      }
    }
    
    return Array.from(files);
  }
}
