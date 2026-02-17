/**
 * API router for Open-Inspect Control Plane.
 */

import type { Env, CreateSessionRequest, CreateSessionResponse } from "./types";
import { generateId, encryptToken } from "./auth/crypto";
import { verifyInternalToken } from "./auth/internal";
import {
  getGitHubAppConfig,
  getInstallationRepository,
  listInstallationRepositories,
} from "./auth/github-app";
import { RepoSecretsStore, RepoSecretsValidationError } from "./db/repo-secrets";
import { SessionIndexStore } from "./db/session-index";

import { RepoMetadataStore } from "./db/repo-metadata";
import { RaygunConfigRepository } from "./db/raygun";
import { RaygunConfigService } from "./services/raygun-config";
import { RaygunMCPClient } from "./services/raygun-mcp-client";
import { listBitbucketRepos, getValidAccessToken as getValidBitbucketToken, getBitbucketRepository } from "./auth/bitbucket";
import type { VCSProvider } from "./types";
import type {
  EnrichedRepository,
  InstallationRepository,
  RepoMetadata,
} from "@open-inspect/shared";
import { createLogger } from "./logger";
import type { CorrelationContext } from "./logger";

const logger = createLogger("router");

const REPOS_CACHE_KEY = "repos:list";
const REPOS_CACHE_TTL_SECONDS = 300; // 5 minutes

/**
 * Request context with correlation IDs propagated to downstream services.
 */
export type RequestContext = CorrelationContext;

/**
 * Create a Request to a Durable Object stub with correlation headers.
 * Ensures trace_id and request_id propagate into the DO.
 */
function internalRequest(url: string, init: RequestInit | undefined, ctx: RequestContext): Request {
  const headers = new Headers(init?.headers);
  headers.set("x-trace-id", ctx.trace_id);
  headers.set("x-request-id", ctx.request_id);
  return new Request(url, { ...init, headers });
}

/**
 * Route configuration.
 */
interface Route {
  method: string;
  pattern: RegExp;
  handler: (
    request: Request,
    env: Env,
    match: RegExpMatchArray,
    ctx: RequestContext
  ) => Promise<Response>;
}

/**
 * Parse route pattern into regex.
 */
function parsePattern(pattern: string): RegExp {
  const regexPattern = pattern.replace(/:(\w+)/g, "(?<$1>[^/]+)");
  return new RegExp(`^${regexPattern}$`);
}

/**
 * Create JSON response.
 */
function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/**
 * Create error response.
 */
function error(message: string, status = 400): Response {
  return json({ error: message }, status);
}

/**
 * Get Durable Object stub for a session.
 * Returns the stub or null if session ID is missing.
 */
function getSessionStub(env: Env, match: RegExpMatchArray): DurableObjectStub | null {
  const sessionId = match.groups?.id;
  if (!sessionId) return null;

  const doId = env.SESSION.idFromName(sessionId);
  return env.SESSION.get(doId);
}

/**
 * Routes that do not require authentication.
 */
const PUBLIC_ROUTES: RegExp[] = [/^\/health$/];

/**
 * Routes that accept sandbox authentication.
 * These are session-specific routes that can be called by sandboxes using their auth token.
 * The sandbox token is validated by the Durable Object.
 */
const SANDBOX_AUTH_ROUTES: RegExp[] = [
  /^\/sessions\/[^/]+\/pr$/, // PR creation from sandbox
];

/**
 * Check if a path matches any public route pattern.
 */
function isPublicRoute(path: string): boolean {
  return PUBLIC_ROUTES.some((pattern) => pattern.test(path));
}

/**
 * Check if a path matches any sandbox auth route pattern.
 */
function isSandboxAuthRoute(path: string): boolean {
  return SANDBOX_AUTH_ROUTES.some((pattern) => pattern.test(path));
}

/**
 * Validate sandbox authentication by checking with the Durable Object.
 * The DO stores the expected sandbox auth token.
 *
 * @param request - The incoming request
 * @param env - Environment bindings
 * @param sessionId - Session ID extracted from path
 * @param ctx - Request correlation context
 * @returns null if authentication passes, or an error Response to return immediately
 */
async function verifySandboxAuth(
  request: Request,
  env: Env,
  sessionId: string,
  ctx: RequestContext
): Promise<Response | null> {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return error("Unauthorized: Missing sandbox token", 401);
  }

  const token = authHeader.slice(7); // Remove "Bearer " prefix

  // Ask the Durable Object to validate this sandbox token
  const doId = env.SESSION.idFromName(sessionId);
  const stub = env.SESSION.get(doId);

  const verifyResponse = await stub.fetch(
    internalRequest(
      "http://internal/internal/verify-sandbox-token",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      },
      ctx
    )
  );

  if (!verifyResponse.ok) {
    const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
    logger.warn("Auth failed: sandbox", {
      event: "auth.sandbox_failed",
      http_path: new URL(request.url).pathname,
      client_ip: clientIP,
      session_id: sessionId,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error("Unauthorized: Invalid sandbox token", 401);
  }

  return null; // Auth passed
}

/**
 * Require internal API authentication for service-to-service calls.
 * Fails closed: returns error response if secret is not configured or token is invalid.
 *
 * @param request - The incoming request
 * @param env - Environment bindings
 * @param path - Request path for logging
 * @param ctx - Request correlation context
 * @returns null if authentication passes, or an error Response to return immediately
 */
async function requireInternalAuth(
  request: Request,
  env: Env,
  path: string,
  ctx: RequestContext
): Promise<Response | null> {
  if (!env.INTERNAL_CALLBACK_SECRET) {
    logger.error("INTERNAL_CALLBACK_SECRET not configured - rejecting request", {
      event: "auth.misconfigured",
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error("Internal authentication not configured", 500);
  }

  const isValid = await verifyInternalToken(
    request.headers.get("Authorization"),
    env.INTERNAL_CALLBACK_SECRET
  );

  if (!isValid) {
    const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
    logger.warn("Auth failed: HMAC", {
      event: "auth.hmac_failed",
      http_path: path,
      client_ip: clientIP,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error("Unauthorized", 401);
  }

  return null; // Auth passed
}

/**
 * Routes definition.
 */
const routes: Route[] = [
  // Health check
  {
    method: "GET",
    pattern: parsePattern("/health"),
    handler: async () => json({ status: "healthy", service: "open-inspect-control-plane" }),
  },

  // Session management
  {
    method: "GET",
    pattern: parsePattern("/sessions"),
    handler: handleListSessions,
  },
  {
    method: "POST",
    pattern: parsePattern("/sessions"),
    handler: handleCreateSession,
  },
  {
    method: "GET",
    pattern: parsePattern("/sessions/:id"),
    handler: handleGetSession,
  },
  {
    method: "DELETE",
    pattern: parsePattern("/sessions/:id"),
    handler: handleDeleteSession,
  },
  {
    method: "POST",
    pattern: parsePattern("/sessions/:id/prompt"),
    handler: handleSessionPrompt,
  },
  {
    method: "POST",
    pattern: parsePattern("/sessions/:id/stop"),
    handler: handleSessionStop,
  },
  {
    method: "GET",
    pattern: parsePattern("/sessions/:id/events"),
    handler: handleSessionEvents,
  },
  {
    method: "GET",
    pattern: parsePattern("/sessions/:id/artifacts"),
    handler: handleSessionArtifacts,
  },
  {
    method: "GET",
    pattern: parsePattern("/sessions/:id/participants"),
    handler: handleSessionParticipants,
  },
  {
    method: "POST",
    pattern: parsePattern("/sessions/:id/participants"),
    handler: handleAddParticipant,
  },
  {
    method: "GET",
    pattern: parsePattern("/sessions/:id/messages"),
    handler: handleSessionMessages,
  },
  {
    method: "POST",
    pattern: parsePattern("/sessions/:id/pr"),
    handler: handleCreatePR,
  },
  {
    method: "POST",
    pattern: parsePattern("/sessions/:id/ws-token"),
    handler: handleSessionWsToken,
  },
  {
    method: "POST",
    pattern: parsePattern("/sessions/:id/archive"),
    handler: handleArchiveSession,
  },
  {
    method: "POST",
    pattern: parsePattern("/sessions/:id/unarchive"),
    handler: handleUnarchiveSession,
  },

  // Repository management
  {
    method: "GET",
    pattern: parsePattern("/repos"),
    handler: handleListRepos,
  },
  {
    method: "PUT",
    pattern: parsePattern("/repos/:owner/:name/metadata"),
    handler: handleUpdateRepoMetadata,
  },
  {
    method: "GET",
    pattern: parsePattern("/repos/:owner/:name/metadata"),
    handler: handleGetRepoMetadata,
  },
  {
    method: "PUT",
    pattern: parsePattern("/repos/:owner/:name/secrets"),
    handler: handleSetRepoSecrets,
  },
  {
    method: "GET",
    pattern: parsePattern("/repos/:owner/:name/secrets"),
    handler: handleListRepoSecrets,
  },
  {
    method: "DELETE",
    pattern: parsePattern("/repos/:owner/:name/secrets/:key"),
    handler: handleDeleteRepoSecret,
  },

  // Raygun configuration management
  {
    method: "GET",
    pattern: parsePattern("/repos/:owner/:name/raygun"),
    handler: handleGetRaygunConfig,
  },
  {
    method: "PUT",
    pattern: parsePattern("/repos/:owner/:name/raygun"),
    handler: handleSetRaygunConfig,
  },
  {
    method: "DELETE",
    pattern: parsePattern("/repos/:owner/:name/raygun"),
    handler: handleDeleteRaygunConfig,
  },

  // Raygun issue retrieval
  {
    method: "GET",
    pattern: parsePattern("/repos/:owner/:name/raygun/issues"),
    handler: handleListRaygunIssues,
  },
  {
    method: "GET",
    pattern: parsePattern("/repos/:owner/:name/raygun/issues/:issueId"),
    handler: handleGetRaygunIssue,
  },
  {
    method: "POST",
    pattern: parsePattern("/repos/:owner/:name/raygun/issues/:issueId/fix"),
    handler: handleCreateRaygunFixSession,
  },
];

/**
 * Match request to route and execute handler.
 */
export async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const startTime = Date.now();

  // Build correlation context
  const ctx: RequestContext = {
    trace_id: request.headers.get("x-trace-id") || crypto.randomUUID(),
    request_id: crypto.randomUUID().slice(0, 8),
  };

  // CORS preflight
  if (method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Max-Age": "86400",
        "x-request-id": ctx.request_id,
        "x-trace-id": ctx.trace_id,
      },
    });
  }

  // Require authentication for non-public routes
  if (!isPublicRoute(path)) {
    // First try HMAC auth (for web app, slack bot, etc.)
    const hmacAuthError = await requireInternalAuth(request, env, path, ctx);

    if (hmacAuthError) {
      // HMAC auth failed - check if this route accepts sandbox auth
      if (isSandboxAuthRoute(path)) {
        // Extract session ID from path (e.g., /sessions/abc123/pr -> abc123)
        const sessionIdMatch = path.match(/^\/sessions\/([^/]+)\//);
        if (sessionIdMatch) {
          const sessionId = sessionIdMatch[1];
          const sandboxAuthError = await verifySandboxAuth(request, env, sessionId, ctx);
          if (!sandboxAuthError) {
            // Sandbox auth passed, continue to route handler
          } else {
            // Both HMAC and sandbox auth failed
            const corsHeaders = new Headers(sandboxAuthError.headers);
            corsHeaders.set("Access-Control-Allow-Origin", "*");
            corsHeaders.set("x-request-id", ctx.request_id);
            corsHeaders.set("x-trace-id", ctx.trace_id);
            return new Response(sandboxAuthError.body, {
              status: sandboxAuthError.status,
              statusText: sandboxAuthError.statusText,
              headers: corsHeaders,
            });
          }
        }
      } else {
        // Not a sandbox auth route, return HMAC auth error
        const corsHeaders = new Headers(hmacAuthError.headers);
        corsHeaders.set("Access-Control-Allow-Origin", "*");
        corsHeaders.set("x-request-id", ctx.request_id);
        corsHeaders.set("x-trace-id", ctx.trace_id);
        return new Response(hmacAuthError.body, {
          status: hmacAuthError.status,
          statusText: hmacAuthError.statusText,
          headers: corsHeaders,
        });
      }
    }
  }

  // Find matching route
  for (const route of routes) {
    if (route.method !== method) continue;

    const match = path.match(route.pattern);
    if (match) {
      let response: Response;
      let outcome: "success" | "error";
      try {
        response = await route.handler(request, env, match, ctx);
        outcome = response.status >= 500 ? "error" : "success";
      } catch (e) {
        const durationMs = Date.now() - startTime;
        const errorMessage = e instanceof Error ? e.message : String(e);
        const errorStack = e instanceof Error ? e.stack : undefined;
        logger.error("http.request", {
          event: "http.request",
          request_id: ctx.request_id,
          trace_id: ctx.trace_id,
          http_method: method,
          http_path: path,
          http_status: 500,
          duration_ms: durationMs,
          outcome: "error",
          error: errorMessage,
          stack: errorStack,
        });
        return json(
          {
            error: "Internal server error",
            detail: errorMessage,
            request_id: ctx.request_id,
            trace_id: ctx.trace_id,
          },
          500
        );
      }

      // Create new response with CORS + correlation headers
      const corsHeaders = new Headers(response.headers);
      corsHeaders.set("Access-Control-Allow-Origin", "*");
      corsHeaders.set("x-request-id", ctx.request_id);
      corsHeaders.set("x-trace-id", ctx.trace_id);

      const durationMs = Date.now() - startTime;
      logger.info("http.request", {
        event: "http.request",
        request_id: ctx.request_id,
        trace_id: ctx.trace_id,
        http_method: method,
        http_path: path,
        http_status: response.status,
        duration_ms: durationMs,
        outcome,
      });

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: corsHeaders,
      });
    }
  }

  return error("Not found", 404);
}

// Session handlers

async function handleListSessions(
  request: Request,
  env: Env,
  _match: RegExpMatchArray,
  _ctx: RequestContext
): Promise<Response> {
  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "50"), 100);
  const offset = parseInt(url.searchParams.get("offset") || "0");
  const status = url.searchParams.get("status") || undefined;
  const excludeStatus = url.searchParams.get("excludeStatus") || undefined;

  const store = new SessionIndexStore(env.DB);
  const result = await store.list({ status, excludeStatus, limit, offset });

  return json({
    sessions: result.sessions,
    total: result.total,
    hasMore: result.hasMore,
  });
}

async function handleCreateSession(
  request: Request,
  env: Env,
  _match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  const body = (await request.json()) as CreateSessionRequest & {
    // Optional GitHub token for PR creation (will be encrypted and stored)
    githubToken?: string;
    // Optional Bitbucket token for PR creation (will be encrypted and stored)
    bitbucketToken?: string;
    bitbucketRefreshToken?: string;
    bitbucketTokenExpiresAt?: number;
    // VCS provider
    vcsProvider?: VCSProvider;
    // User info
    userId?: string;
    githubLogin?: string;
    githubName?: string;
    githubEmail?: string;
    // Bitbucket user info
    bitbucketUuid?: string;
    bitbucketLogin?: string;
    bitbucketDisplayName?: string;
    bitbucketEmail?: string;
  };

  if (!body.repoOwner || !body.repoName) {
    return error("repoOwner and repoName are required");
  }

  // Normalize repo identifiers to lowercase for consistent storage
  const repoOwner = body.repoOwner.toLowerCase();
  const repoName = body.repoName.toLowerCase();

  // VCS provider (infer from tokens if not specified, default to github)
  let vcsProvider: VCSProvider = body.vcsProvider || "github";

  // If vcsProvider is default but we have bitbucket token, infer bitbucket
  if (!body.vcsProvider && body.bitbucketToken) {
    vcsProvider = "bitbucket";
  }

  let repoId: number | undefined;

  if (vcsProvider === "github") {
    try {
      const resolved = await resolveInstalledRepo(env, repoOwner, repoName);
      if (!resolved) {
        return error("Repository is not installed for the GitHub App", 404);
      }
      repoId = resolved.repoId;
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      logger.error("Failed to resolve repository", {
        error: message,
        repo_owner: repoOwner,
        repo_name: repoName,
      });
      // Return 500 only if it's a configuration error, otherwise 404/400 might be more appropriate
      // But keeping existing behavior for now, just clearer logging
      return json(
        {
          error: message === "GitHub App not configured" ? message : "Failed to resolve repository",
          detail: message,
        },
        500
      );
    }
  } else if (vcsProvider === "bitbucket") {
    // Verify Bitbucket repository access if token is provided
    if (body.bitbucketToken) {
      try {
        const repo = await getBitbucketRepository(body.bitbucketToken, repoOwner, repoName);
        // Bitbucket UUIDs are strings, but our DB expects integer repoId.
        // We can hash the UUID to get a stable integer ID or just leave undefined
        // for now as repoId is primarily for GitHub App installation checks.
        // However, we can use the integer logic if needed later.
      } catch (e) {
        const message = e instanceof Error ? e.message : String(e);
        logger.error("Failed to resolve Bitbucket repository", {
          error: message,
          repo_owner: repoOwner,
          repo_name: repoName,
        });
        return json(
          {
            error: "Failed to resolve Bitbucket repository",
            detail: message,
          },
          404
        );
      }
    }
  }

  // User info from direct params
  const userId = body.userId || "anonymous";
  const githubLogin = body.githubLogin;
  const githubName = body.githubName;
  const githubEmail = body.githubEmail;
  let githubTokenEncrypted: string | null = null;

  // Bitbucket user info
  const bitbucketUuid = body.bitbucketUuid;
  const bitbucketLogin = body.bitbucketLogin;
  const bitbucketDisplayName = body.bitbucketDisplayName;
  const bitbucketEmail = body.bitbucketEmail;
  let bitbucketTokenEncrypted: string | null = null;
  let bitbucketRefreshTokenEncrypted: string | null = null;
  const bitbucketTokenExpiresAt = body.bitbucketTokenExpiresAt || null;

  // If GitHub token provided, encrypt it
  if (body.githubToken && env.TOKEN_ENCRYPTION_KEY) {
    try {
      githubTokenEncrypted = await encryptToken(body.githubToken, env.TOKEN_ENCRYPTION_KEY);
    } catch (e) {
      logger.error("Failed to encrypt GitHub token", {
        error: e instanceof Error ? e : String(e),
      });
      return error("Failed to process GitHub token", 500);
    }
  }

  // If Bitbucket tokens provided, encrypt them
  if (body.bitbucketToken && env.TOKEN_ENCRYPTION_KEY) {
    try {
      bitbucketTokenEncrypted = await encryptToken(body.bitbucketToken, env.TOKEN_ENCRYPTION_KEY);
      if (body.bitbucketRefreshToken) {
        bitbucketRefreshTokenEncrypted = await encryptToken(
          body.bitbucketRefreshToken,
          env.TOKEN_ENCRYPTION_KEY
        );
      }
    } catch (e) {
      logger.error("Failed to encrypt Bitbucket token", {
        error: e instanceof Error ? e : String(e),
      });
      return error("Failed to process Bitbucket token", 500);
    }
  }

  // Generate session ID
  const sessionId = generateId();

  // Get Durable Object
  const doId = env.SESSION.idFromName(sessionId);
  const stub = env.SESSION.get(doId);

  // Initialize session with user info and optional encrypted token
  const initResponse = await stub.fetch(
    internalRequest(
      "http://internal/internal/init",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sessionName: sessionId, // Pass the session name for WebSocket routing
          repoOwner,
          repoName,
          repoId,
          title: body.title,
          model: body.model || "claude-haiku-4-5", // Default to haiku for cost efficiency
          vcsProvider,
          // GitHub user info
          userId,
          githubLogin,
          githubName,
          githubEmail,
          githubTokenEncrypted, // Pass encrypted token to store with owner
          // Bitbucket user info
          bitbucketUuid,
          bitbucketLogin,
          bitbucketDisplayName,
          bitbucketEmail,
          bitbucketTokenEncrypted,
          bitbucketRefreshTokenEncrypted,
          bitbucketTokenExpiresAt,
        }),
      },
      ctx
    )
  );

  if (!initResponse.ok) {
    const initError = await initResponse.text().catch(() => "unknown");
    logger.error("Failed to initialize session via Durable Object", {
      event: "session.init_failed",
      session_id: sessionId,
      repo_owner: repoOwner,
      repo_name: repoName,
      vcs_provider: vcsProvider,
      do_status: initResponse.status,
      do_error: initError,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return json(
      {
        error: "Failed to create session",
        detail: `Durable Object init failed (${initResponse.status}): ${initError}`,
        request_id: ctx.request_id,
        trace_id: ctx.trace_id,
      },
      500
    );
  }

  // Store session in D1 index for listing
  const now = Date.now();
  const sessionStore = new SessionIndexStore(env.DB);
  await sessionStore.create({
    id: sessionId,
    title: body.title || null,
    repoOwner,
    repoName,
    model: body.model || "claude-haiku-4-5",
      vcsProvider,
    status: "created",
    createdAt: now,
    updatedAt: now,
  });

  const result: CreateSessionResponse = {
    sessionId,
    status: "created",
  };

  return json(result, 201);
}

async function handleGetSession(
  request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  const sessionId = match.groups?.id;
  if (!sessionId) return error("Session ID required");

  const doId = env.SESSION.idFromName(sessionId);
  const stub = env.SESSION.get(doId);

  const response = await stub.fetch(
    internalRequest("http://internal/internal/state", undefined, ctx)
  );

  if (!response.ok) {
    return error("Session not found", 404);
  }

  return response;
}

async function handleDeleteSession(
  request: Request,
  env: Env,
  match: RegExpMatchArray,
  _ctx: RequestContext
): Promise<Response> {
  const sessionId = match.groups?.id;
  if (!sessionId) return error("Session ID required");

  // Delete from D1 index
  const sessionStore = new SessionIndexStore(env.DB);
  await sessionStore.delete(sessionId);

  // Note: Durable Object data will be garbage collected by Cloudflare
  // when no longer referenced. We could also call a cleanup method on the DO.

  return json({ status: "deleted", sessionId });
}

async function handleSessionPrompt(
  request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  const sessionId = match.groups?.id;
  if (!sessionId) return error("Session ID required");

  const body = (await request.json()) as {
    content: string;
    authorId?: string;
    source?: string;
    attachments?: Array<{ type: string; name: string; url?: string }>;
    callbackContext?: {
      channel: string;
      threadTs: string;
      repoFullName: string;
      model: string;
    };
  };

  if (!body.content) {
    return error("content is required");
  }

  const doId = env.SESSION.idFromName(sessionId);
  const stub = env.SESSION.get(doId);

  const response = await stub.fetch(
    internalRequest(
      "http://internal/internal/prompt",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: body.content,
          authorId: body.authorId || "anonymous",
          source: body.source || "web",
          attachments: body.attachments,
          callbackContext: body.callbackContext,
        }),
      },
      ctx
    )
  );

  return response;
}

async function handleSessionStop(
  _request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  const stub = getSessionStub(env, match);
  if (!stub) return error("Session ID required");

  return stub.fetch(internalRequest("http://internal/internal/stop", { method: "POST" }, ctx));
}

async function handleSessionEvents(
  request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  const stub = getSessionStub(env, match);
  if (!stub) return error("Session ID required");

  const url = new URL(request.url);
  return stub.fetch(
    internalRequest(`http://internal/internal/events${url.search}`, undefined, ctx)
  );
}

async function handleSessionArtifacts(
  _request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  const stub = getSessionStub(env, match);
  if (!stub) return error("Session ID required");

  return stub.fetch(internalRequest("http://internal/internal/artifacts", undefined, ctx));
}

async function handleSessionParticipants(
  _request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  const stub = getSessionStub(env, match);
  if (!stub) return error("Session ID required");

  return stub.fetch(internalRequest("http://internal/internal/participants", undefined, ctx));
}

async function handleAddParticipant(
  request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  const sessionId = match.groups?.id;
  if (!sessionId) return error("Session ID required");

  const body = await request.json();

  const doId = env.SESSION.idFromName(sessionId);
  const stub = env.SESSION.get(doId);

  const response = await stub.fetch(
    internalRequest(
      "http://internal/internal/participants",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
      ctx
    )
  );

  return response;
}

async function handleSessionMessages(
  request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  const stub = getSessionStub(env, match);
  if (!stub) return error("Session ID required");

  const url = new URL(request.url);
  return stub.fetch(
    internalRequest(`http://internal/internal/messages${url.search}`, undefined, ctx)
  );
}

async function handleCreatePR(
  request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  const sessionId = match.groups?.id;
  if (!sessionId) return error("Session ID required");

  const body = (await request.json()) as {
    title: string;
    body: string;
    baseBranch?: string;
  };

  if (!body.title || !body.body) {
    return error("title and body are required");
  }

  const doId = env.SESSION.idFromName(sessionId);
  const stub = env.SESSION.get(doId);

  const response = await stub.fetch(
    internalRequest(
      "http://internal/internal/create-pr",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: body.title,
          body: body.body,
          baseBranch: body.baseBranch,
        }),
      },
      ctx
    )
  );

  return response;
}

async function handleSessionWsToken(
  request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  const sessionId = match.groups?.id;
  if (!sessionId) return error("Session ID required");

  const body = (await request.json()) as {
    userId: string;
    githubUserId?: string;
    githubLogin?: string;
    githubName?: string;
    githubEmail?: string;
    githubToken?: string; // User's GitHub OAuth token for PR creation
    githubTokenExpiresAt?: number; // Token expiry timestamp in milliseconds
    githubRefreshToken?: string; // GitHub OAuth refresh token for server-side renewal
    // Bitbucket fields
    bitbucketUuid?: string;
    bitbucketLogin?: string;
    bitbucketDisplayName?: string;
    bitbucketEmail?: string;
    bitbucketToken?: string;
    bitbucketRefreshToken?: string;
    bitbucketTokenExpiresAt?: number;
  };

  if (!body.userId) {
    return error("userId is required");
  }

  // Encrypt the GitHub token if provided
  let githubTokenEncrypted: string | null = null;
  if (body.githubToken && env.TOKEN_ENCRYPTION_KEY) {
    try {
      githubTokenEncrypted = await encryptToken(body.githubToken, env.TOKEN_ENCRYPTION_KEY);
    } catch (e) {
      logger.error("Failed to encrypt GitHub token", {
        error: e instanceof Error ? e : String(e),
      });
      // Continue without token - PR creation will fail if this user triggers it
    }
  }

  // Encrypt the GitHub refresh token if provided
  let githubRefreshTokenEncrypted: string | null = null;
  if (body.githubRefreshToken && env.TOKEN_ENCRYPTION_KEY) {
    try {
      githubRefreshTokenEncrypted = await encryptToken(
        body.githubRefreshToken,
        env.TOKEN_ENCRYPTION_KEY
      );
    } catch (e) {
      logger.error("Failed to encrypt GitHub refresh token", {
        error: e instanceof Error ? e : String(e),
      });
    }
  }

  // Encrypt the Bitbucket token if provided
  let bitbucketTokenEncrypted: string | null = null;
  let bitbucketRefreshTokenEncrypted: string | null = null;
  if (body.bitbucketToken && env.TOKEN_ENCRYPTION_KEY) {
    try {
      bitbucketTokenEncrypted = await encryptToken(body.bitbucketToken, env.TOKEN_ENCRYPTION_KEY);
      if (body.bitbucketRefreshToken) {
        bitbucketRefreshTokenEncrypted = await encryptToken(
          body.bitbucketRefreshToken,
          env.TOKEN_ENCRYPTION_KEY
        );
      }
    } catch (e) {
      logger.error("Failed to encrypt Bitbucket token", {
        error: e instanceof Error ? e : String(e),
      });
    }
  }

  const doId = env.SESSION.idFromName(sessionId);
  const stub = env.SESSION.get(doId);

  const response = await stub.fetch(
    internalRequest(
      "http://internal/internal/ws-token",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          userId: body.userId,
          githubUserId: body.githubUserId,
          githubLogin: body.githubLogin,
          githubName: body.githubName,
          githubEmail: body.githubEmail,
          githubTokenEncrypted,
          githubRefreshTokenEncrypted,
          githubTokenExpiresAt: body.githubTokenExpiresAt,
          bitbucketUuid: body.bitbucketUuid,
          bitbucketLogin: body.bitbucketLogin,
          bitbucketDisplayName: body.bitbucketDisplayName,
          bitbucketEmail: body.bitbucketEmail,
          bitbucketTokenEncrypted,
          bitbucketRefreshTokenEncrypted,
          bitbucketTokenExpiresAt: body.bitbucketTokenExpiresAt,
        }),
      },
      ctx
    )
  );

  return response;
}

async function handleArchiveSession(
  request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  const sessionId = match.groups?.id;
  if (!sessionId) return error("Session ID required");

  // Parse userId from request body for authorization
  let userId: string | undefined;
  try {
    const body = (await request.json()) as { userId?: string };
    userId = body.userId;
  } catch {
    // Body parsing failed, continue without userId
  }

  const doId = env.SESSION.idFromName(sessionId);
  const stub = env.SESSION.get(doId);

  const response = await stub.fetch(
    internalRequest(
      "http://internal/internal/archive",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId }),
      },
      ctx
    )
  );

  if (response.ok) {
    // Update D1 index
    const sessionStore = new SessionIndexStore(env.DB);
    const updated = await sessionStore.updateStatus(sessionId, "archived");
    if (!updated) {
      logger.warn("Session not found in D1 index during archive", { session_id: sessionId });
    }
  }

  return response;
}

async function handleUnarchiveSession(
  request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  const sessionId = match.groups?.id;
  if (!sessionId) return error("Session ID required");

  // Parse userId from request body for authorization
  let userId: string | undefined;
  try {
    const body = (await request.json()) as { userId?: string };
    userId = body.userId;
  } catch {
    // Body parsing failed, continue without userId
  }

  const doId = env.SESSION.idFromName(sessionId);
  const stub = env.SESSION.get(doId);

  const response = await stub.fetch(
    internalRequest(
      "http://internal/internal/unarchive",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId }),
      },
      ctx
    )
  );

  if (response.ok) {
    // Update D1 index
    const sessionStore = new SessionIndexStore(env.DB);
    const updated = await sessionStore.updateStatus(sessionId, "active");
    if (!updated) {
      logger.warn("Session not found in D1 index during unarchive", { session_id: sessionId });
    }
  }

  return response;
}

// Repository handlers

async function resolveInstalledRepo(
  env: Env,
  repoOwner: string,
  repoName: string
): Promise<{ repoId: number; repoOwner: string; repoName: string } | null> {
  const appConfig = getGitHubAppConfig(env);
  if (!appConfig) {
    throw new Error("GitHub App not configured");
  }

  const repo = await getInstallationRepository(appConfig, repoOwner, repoName);
  if (!repo) {
    return null;
  }

  return {
    repoId: repo.id,
    repoOwner: repoOwner.toLowerCase(),
    repoName: repoName.toLowerCase(),
  };
}

/**
 * Cached repos list structure stored in KV.
 */
interface CachedReposList {
  repos: EnrichedRepository[];
  cachedAt: string;
}

/**
 * List all repositories accessible via the GitHub App installation or Bitbucket user token.
 * Results are cached in KV for 5 minutes to avoid rate limits.
 * KV is shared across isolates, so cache invalidation is consistent.
 *
 * For GitHub: Uses GitHub App installation token
 * For Bitbucket: Uses user's OAuth token from X-User-Token header
 */
async function handleListRepos(
  request: Request,
  env: Env,
  _match: RegExpMatchArray,
  _ctx: RequestContext
): Promise<Response> {
  // Determine VCS provider from header
  const vcsProvider = (request.headers.get("X-VCS-Provider") || "github") as VCSProvider;
  const userToken = request.headers.get("X-User-Token");

  // Use provider-specific cache keys
  const CACHE_KEY = vcsProvider === "bitbucket" ? "repos:list:bitbucket" : "repos:list";
  const CACHE_TTL = 300; // 5 minutes

  // Check KV cache first
  try {
    const cached = await env.REPOS_CACHE.get<CachedReposList>(REPOS_CACHE_KEY, "json");
    if (cached) {
      return json({
        repos: cached.repos,
        cached: true,
        cachedAt: cached.cachedAt,
      });
    }
  } catch (e) {
    logger.warn("Failed to read repos cache", { error: e instanceof Error ? e : String(e) });
  }

  // Handle Bitbucket repository listing
  if (vcsProvider === "bitbucket") {
    if (!userToken) {
      return error("Bitbucket access token required (X-User-Token header)", 401);
    }

    try {
      const bitbucketRepos = await listBitbucketRepos(userToken);

      // Normalize Bitbucket repos to match the EnrichedRepository interface
      const repos: EnrichedRepository[] = bitbucketRepos.map((repo) => ({
        id: repo.uuid,
        owner: repo.workspace?.slug || repo.owner?.username || "",
        name: repo.slug,
        fullName: repo.full_name,
        description: repo.description || null,
        private: repo.is_private,
        defaultBranch: repo.mainbranch?.name || "main",
      }));

      // Cache the results
      const cachedAt = new Date().toISOString();
      const cacheData: CachedReposList = { repos, cachedAt };

      try {
        await env.SESSION_INDEX.put(CACHE_KEY, JSON.stringify(cacheData), {
          expirationTtl: CACHE_TTL,
        });
      } catch (e) {
        logger.warn("Failed to cache Bitbucket repos list", { error: e instanceof Error ? e : String(e) });
      }

      return json({
        repos,
        cached: false,
        cachedAt,
      });
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      logger.error("Failed to list Bitbucket repositories", {
        error: message,
      });
      return json(
        {
          error: "Failed to fetch repositories from Bitbucket",
          detail: message,
        },
        500
      );
    }
  }

  // GitHub: Use GitHub App installation
  const appConfig = getGitHubAppConfig(env);
  if (!appConfig) {
    return error("GitHub App not configured", 500);
  }

  // Fetch repositories from GitHub App installation
  let repos: InstallationRepository[];
  try {
    repos = await listInstallationRepositories(appConfig);
  } catch (e) {
    logger.error("Failed to list installation repositories", {
      error: e instanceof Error ? e : String(e),
    });
    return error("Failed to fetch repositories from GitHub", 500);
  }

  // Batch-fetch metadata from D1
  const metadataStore = new RepoMetadataStore(env.DB);
  let metadataMap: Map<string, RepoMetadata>;
  try {
    metadataMap = await metadataStore.getBatch(
      repos.map((r) => ({ owner: r.owner, name: r.name }))
    );
  } catch (e) {
    logger.warn("Failed to fetch repo metadata batch", {
      error: e instanceof Error ? e : String(e),
    });
    metadataMap = new Map();
  }

  // Enrich repos with stored metadata
  const enrichedRepos: EnrichedRepository[] = repos.map((repo) => {
    const key = `${repo.owner.toLowerCase()}/${repo.name.toLowerCase()}`;
    const metadata = metadataMap.get(key);
    return metadata ? { ...repo, metadata } : repo;
  });

  // Cache the results in KV with TTL
  const cachedAt = new Date().toISOString();
  try {
    await env.REPOS_CACHE.put(REPOS_CACHE_KEY, JSON.stringify({ repos: enrichedRepos, cachedAt }), {
      expirationTtl: REPOS_CACHE_TTL_SECONDS,
    });
  } catch (e) {
    logger.warn("Failed to cache repos list", { error: e instanceof Error ? e : String(e) });
  }

  return json({
    repos: enrichedRepos,
    cached: false,
    cachedAt,
  });
}

/**
 * Update metadata for a specific repository.
 * This allows storing custom descriptions, aliases, and channel associations.
 */
async function handleUpdateRepoMetadata(
  request: Request,
  env: Env,
  match: RegExpMatchArray,
  _ctx: RequestContext
): Promise<Response> {
  const owner = match.groups?.owner;
  const name = match.groups?.name;

  if (!owner || !name) {
    return error("Owner and name are required");
  }

  const body = (await request.json()) as RepoMetadata;

  // Validate and clean the metadata structure (remove undefined fields)
  const metadata = Object.fromEntries(
    Object.entries({
      description: body.description,
      aliases: Array.isArray(body.aliases) ? body.aliases : undefined,
      channelAssociations: Array.isArray(body.channelAssociations)
        ? body.channelAssociations
        : undefined,
      keywords: Array.isArray(body.keywords) ? body.keywords : undefined,
    }).filter(([, v]) => v !== undefined)
  ) as RepoMetadata;

  const metadataStore = new RepoMetadataStore(env.DB);

  try {
    await metadataStore.upsert(owner, name, metadata);

    // Invalidate the KV repos cache so next fetch includes updated metadata
    await env.REPOS_CACHE.delete(REPOS_CACHE_KEY);

    // Return normalized repo identifier
    const normalizedRepo = `${owner.toLowerCase()}/${name.toLowerCase()}`;
    return json({
      status: "updated",
      repo: normalizedRepo,
      metadata,
    });
  } catch (e) {
    logger.error("Failed to update repo metadata", {
      error: e instanceof Error ? e : String(e),
    });
    return error("Failed to update metadata", 500);
  }
}

/**
 * Get metadata for a specific repository.
 */
async function handleGetRepoMetadata(
  request: Request,
  env: Env,
  match: RegExpMatchArray,
  _ctx: RequestContext
): Promise<Response> {
  const owner = match.groups?.owner;
  const name = match.groups?.name;

  if (!owner || !name) {
    return error("Owner and name are required");
  }

  const normalizedRepo = `${owner.toLowerCase()}/${name.toLowerCase()}`;
  const metadataStore = new RepoMetadataStore(env.DB);

  try {
    const metadata = await metadataStore.get(owner, name);

    return json({
      repo: normalizedRepo,
      metadata: metadata ?? null,
    });
  } catch (e) {
    logger.error("Failed to get repo metadata", { error: e instanceof Error ? e : String(e) });
    return error("Failed to get metadata", 500);
  }
}

/**
 * Upsert secrets for a repository.
 */
async function handleSetRepoSecrets(
  request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  if (!env.DB) {
    return error("Secrets storage is not configured", 503);
  }
  if (!env.REPO_SECRETS_ENCRYPTION_KEY) {
    return error("REPO_SECRETS_ENCRYPTION_KEY not configured", 500);
  }

  const owner = match.groups?.owner;
  const name = match.groups?.name;
  if (!owner || !name) {
    return error("Owner and name are required");
  }

  let resolved;
  try {
    resolved = await resolveInstalledRepo(env, owner, name);
    if (!resolved) {
      return error("Repository is not installed for the GitHub App", 404);
    }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    logger.error("Failed to resolve repository for secrets", {
      error: message,
      repo_owner: owner,
      repo_name: name,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error(
      message === "GitHub App not configured" ? message : "Failed to resolve repository",
      500
    );
  }

  let body: { secrets?: Record<string, string> };
  try {
    body = (await request.json()) as { secrets?: Record<string, string> };
  } catch {
    return error("Invalid JSON body", 400);
  }

  if (!body?.secrets || typeof body.secrets !== "object") {
    return error("Request body must include secrets object", 400);
  }

  const store = new RepoSecretsStore(env.DB, env.REPO_SECRETS_ENCRYPTION_KEY);

  try {
    const result = await store.setSecrets(
      resolved.repoId,
      resolved.repoOwner,
      resolved.repoName,
      body.secrets
    );

    logger.info("repo.secrets_updated", {
      event: "repo.secrets_updated",
      repo_id: resolved.repoId,
      repo_owner: resolved.repoOwner,
      repo_name: resolved.repoName,
      keys_count: result.keys.length,
      created: result.created,
      updated: result.updated,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });

    return json({
      status: "updated",
      repo: `${resolved.repoOwner}/${resolved.repoName}`,
      keys: result.keys,
      created: result.created,
      updated: result.updated,
    });
  } catch (e) {
    if (e instanceof RepoSecretsValidationError) {
      return error(e.message, 400);
    }
    logger.error("Failed to update repo secrets", {
      error: e instanceof Error ? e.message : String(e),
      repo_id: resolved.repoId,
      repo_owner: resolved.repoOwner,
      repo_name: resolved.repoName,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error("Secrets storage unavailable", 503);
  }
}

/**
 * List secret keys for a repository.
 */
async function handleListRepoSecrets(
  _request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  if (!env.DB) {
    return error("Secrets storage is not configured", 503);
  }
  if (!env.REPO_SECRETS_ENCRYPTION_KEY) {
    return error("REPO_SECRETS_ENCRYPTION_KEY not configured", 500);
  }

  const owner = match.groups?.owner;
  const name = match.groups?.name;
  if (!owner || !name) {
    return error("Owner and name are required");
  }

  let resolved;
  try {
    resolved = await resolveInstalledRepo(env, owner, name);
    if (!resolved) {
      return error("Repository is not installed for the GitHub App", 404);
    }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    logger.error("Failed to resolve repository for secrets list", {
      error: message,
      repo_owner: owner,
      repo_name: name,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error(
      message === "GitHub App not configured" ? message : "Failed to resolve repository",
      500
    );
  }

  const store = new RepoSecretsStore(env.DB, env.REPO_SECRETS_ENCRYPTION_KEY);

  try {
    const secrets = await store.listSecretKeys(resolved.repoId);

    logger.info("repo.secrets_listed", {
      event: "repo.secrets_listed",
      repo_id: resolved.repoId,
      repo_owner: resolved.repoOwner,
      repo_name: resolved.repoName,
      keys_count: secrets.length,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });

    return json({
      repo: `${resolved.repoOwner}/${resolved.repoName}`,
      secrets,
    });
  } catch (e) {
    logger.error("Failed to list repo secrets", {
      error: e instanceof Error ? e.message : String(e),
      repo_id: resolved.repoId,
      repo_owner: resolved.repoOwner,
      repo_name: resolved.repoName,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error("Secrets storage unavailable", 503);
  }
}

/**
 * Delete a secret for a repository.
 */
async function handleDeleteRepoSecret(
  _request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  if (!env.DB) {
    return error("Secrets storage is not configured", 503);
  }
  if (!env.REPO_SECRETS_ENCRYPTION_KEY) {
    return error("REPO_SECRETS_ENCRYPTION_KEY not configured", 500);
  }

  const owner = match.groups?.owner;
  const name = match.groups?.name;
  const key = match.groups?.key;
  if (!owner || !name || !key) {
    return error("Owner, name, and key are required");
  }

  let resolved;
  try {
    resolved = await resolveInstalledRepo(env, owner, name);
    if (!resolved) {
      return error("Repository is not installed for the GitHub App", 404);
    }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    logger.error("Failed to resolve repository for secrets delete", {
      error: message,
      repo_owner: owner,
      repo_name: name,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error(
      message === "GitHub App not configured" ? message : "Failed to resolve repository",
      500
    );
  }

  const store = new RepoSecretsStore(env.DB, env.REPO_SECRETS_ENCRYPTION_KEY);

  try {
    store.validateKey(store.normalizeKey(key));

    const deleted = await store.deleteSecret(resolved.repoId, key);
    if (!deleted) {
      return error("Secret not found", 404);
    }

    logger.info("repo.secret_deleted", {
      event: "repo.secret_deleted",
      repo_id: resolved.repoId,
      repo_owner: resolved.repoOwner,
      repo_name: resolved.repoName,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });

    return json({
      status: "deleted",
      repo: `${resolved.repoOwner}/${resolved.repoName}`,
      key: store.normalizeKey(key),
    });
  } catch (e) {
    if (e instanceof RepoSecretsValidationError) {
      return error(e.message, 400);
    }
    logger.error("Failed to delete repo secret", {
      error: e instanceof Error ? e.message : String(e),
      repo_id: resolved.repoId,
      repo_owner: resolved.repoOwner,
      repo_name: resolved.repoName,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error("Secrets storage unavailable", 503);
  }
}

// Raygun configuration handlers

/**
 * Get Raygun configuration for a repository.
 */
async function handleGetRaygunConfig(
  _request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  if (!env.DB) {
    return error("Raygun configuration storage is not configured", 503);
  }
  if (!env.REPO_SECRETS_ENCRYPTION_KEY) {
    return error("REPO_SECRETS_ENCRYPTION_KEY not configured", 500);
  }

  const owner = match.groups?.owner;
  const name = match.groups?.name;
  if (!owner || !name) {
    return error("Owner and name are required");
  }

  let resolved;
  try {
    resolved = await resolveInstalledRepo(env, owner, name);
    if (!resolved) {
      return error("Repository is not installed for the GitHub App", 404);
    }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    logger.error("Failed to resolve repository for Raygun config", {
      error: message,
      repo_owner: owner,
      repo_name: name,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error(
      message === "GitHub App not configured" ? message : "Failed to resolve repository",
      500
    );
  }

  const repository = new RaygunConfigRepository(env.DB, env.REPO_SECRETS_ENCRYPTION_KEY);
  const service = new RaygunConfigService(repository);

  try {
    const config = await service.getConfig(resolved.repoId);

    if (!config) {
      return error("Raygun configuration not found", 404);
    }

    logger.info("raygun.config_retrieved", {
      event: "raygun.config_retrieved",
      repo_id: resolved.repoId,
      repo_owner: resolved.repoOwner,
      repo_name: resolved.repoName,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });

    return json({
      applicationId: config.applicationId,
    });
  } catch (e) {
    logger.error("Failed to get Raygun configuration", {
      error: e instanceof Error ? e.message : String(e),
      repo_id: resolved.repoId,
      repo_owner: resolved.repoOwner,
      repo_name: resolved.repoName,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error("Failed to retrieve Raygun configuration", 500);
  }
}

/**
 * Create or update Raygun configuration for a repository.
 */
async function handleSetRaygunConfig(
  request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  if (!env.DB) {
    return error("Raygun configuration storage is not configured", 503);
  }
  if (!env.REPO_SECRETS_ENCRYPTION_KEY) {
    return error("REPO_SECRETS_ENCRYPTION_KEY not configured", 500);
  }

  const owner = match.groups?.owner;
  const name = match.groups?.name;
  if (!owner || !name) {
    return error("Owner and name are required");
  }

  let resolved;
  try {
    resolved = await resolveInstalledRepo(env, owner, name);
    if (!resolved) {
      return error("Repository is not installed for the GitHub App", 404);
    }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    logger.error("Failed to resolve repository for Raygun config", {
      error: message,
      repo_owner: owner,
      repo_name: name,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error(
      message === "GitHub App not configured" ? message : "Failed to resolve repository",
      500
    );
  }

  let body: { applicationId?: string };
  try {
    body = (await request.json()) as { applicationId?: string };
  } catch {
    return error("Invalid JSON body", 400);
  }

  if (!body?.applicationId || typeof body.applicationId !== "string") {
    return error("Request body must include applicationId", 400);
  }

  const repository = new RaygunConfigRepository(env.DB, env.REPO_SECRETS_ENCRYPTION_KEY);
  const service = new RaygunConfigService(repository);

  try {
    const config = await service.setConfig(resolved.repoId, body.applicationId);

    logger.info("raygun.config_updated", {
      event: "raygun.config_updated",
      repo_id: resolved.repoId,
      repo_owner: resolved.repoOwner,
      repo_name: resolved.repoName,
      config_id: config.id,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });

    return json({
      status: "updated",
      repo: `${resolved.repoOwner}/${resolved.repoName}`,
      applicationId: config.applicationId,
    });
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    
    // Check if it's a validation error
    if (message.includes("Invalid Application ID format")) {
      return error(message, 400);
    }

    logger.error("Failed to set Raygun configuration", {
      error: message,
      repo_id: resolved.repoId,
      repo_owner: resolved.repoOwner,
      repo_name: resolved.repoName,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error("Failed to update Raygun configuration", 500);
  }
}

/**
 * Delete Raygun configuration for a repository.
 */
async function handleDeleteRaygunConfig(
  _request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  if (!env.DB) {
    return error("Raygun configuration storage is not configured", 503);
  }
  if (!env.REPO_SECRETS_ENCRYPTION_KEY) {
    return error("REPO_SECRETS_ENCRYPTION_KEY not configured", 500);
  }

  const owner = match.groups?.owner;
  const name = match.groups?.name;
  if (!owner || !name) {
    return error("Owner and name are required");
  }

  let resolved;
  try {
    resolved = await resolveInstalledRepo(env, owner, name);
    if (!resolved) {
      return error("Repository is not installed for the GitHub App", 404);
    }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    logger.error("Failed to resolve repository for Raygun config deletion", {
      error: message,
      repo_owner: owner,
      repo_name: name,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error(
      message === "GitHub App not configured" ? message : "Failed to resolve repository",
      500
    );
  }

  const repository = new RaygunConfigRepository(env.DB, env.REPO_SECRETS_ENCRYPTION_KEY);
  const service = new RaygunConfigService(repository);

  try {
    await service.deleteConfig(resolved.repoId);

    logger.info("raygun.config_deleted", {
      event: "raygun.config_deleted",
      repo_id: resolved.repoId,
      repo_owner: resolved.repoOwner,
      repo_name: resolved.repoName,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });

    return json({
      status: "deleted",
      repo: `${resolved.repoOwner}/${resolved.repoName}`,
    });
  } catch (e) {
    logger.error("Failed to delete Raygun configuration", {
      error: e instanceof Error ? e.message : String(e),
      repo_id: resolved.repoId,
      repo_owner: resolved.repoOwner,
      repo_name: resolved.repoName,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error("Failed to delete Raygun configuration", 500);
  }
}

// Raygun issue retrieval handlers

/**
 * List Raygun issues for a repository.
 */
async function handleListRaygunIssues(
  _request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  if (!env.DB) {
    return error("Raygun configuration storage is not configured", 503);
  }
  if (!env.REPO_SECRETS_ENCRYPTION_KEY) {
    return error("REPO_SECRETS_ENCRYPTION_KEY not configured", 500);
  }
  if (!env.RAYGUN_MCP_URL) {
    return error("RAYGUN_MCP_URL not configured", 500);
  }

  const owner = match.groups?.owner;
  const name = match.groups?.name;
  if (!owner || !name) {
    return error("Owner and name are required");
  }

  let resolved;
  try {
    resolved = await resolveInstalledRepo(env, owner, name);
    if (!resolved) {
      return error("Repository is not installed for the GitHub App", 404);
    }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    logger.error("Failed to resolve repository for Raygun issues", {
      error: message,
      repo_owner: owner,
      repo_name: name,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error(
      message === "GitHub App not configured" ? message : "Failed to resolve repository",
      500
    );
  }

  // Get Raygun configuration
  const repository = new RaygunConfigRepository(env.DB, env.REPO_SECRETS_ENCRYPTION_KEY);
  const service = new RaygunConfigService(repository);

  let config;
  try {
    config = await service.getConfig(resolved.repoId);
    if (!config) {
      return error("Please configure Raygun for this repository first.", 404);
    }
  } catch (e) {
    logger.error("Failed to get Raygun configuration for issues list", {
      error: e instanceof Error ? e.message : String(e),
      repo_id: resolved.repoId,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error("Failed to retrieve Raygun configuration", 500);
  }

  // Fetch issues from Raygun MCP
  const mcpClient = new RaygunMCPClient(env.RAYGUN_MCP_URL);

  try {
    const issues = await mcpClient.listIssues(config.applicationId);

    // Sort issues by lastSeenAt descending (most recent first)
    issues.sort((a, b) => b.lastSeenAt.getTime() - a.lastSeenAt.getTime());

    logger.info("raygun.issues_listed", {
      event: "raygun.issues_listed",
      repo_id: resolved.repoId,
      repo_owner: resolved.repoOwner,
      repo_name: resolved.repoName,
      issues_count: issues.length,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });

    return json({
      issues,
    });
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    logger.error("Failed to list Raygun issues", {
      error: message,
      repo_id: resolved.repoId,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    
    // Return user-friendly error message
    return error(message, 500);
  }
}

/**
 * Get detailed information about a specific Raygun issue.
 */
async function handleGetRaygunIssue(
  _request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  if (!env.DB) {
    return error("Raygun configuration storage is not configured", 503);
  }
  if (!env.REPO_SECRETS_ENCRYPTION_KEY) {
    return error("REPO_SECRETS_ENCRYPTION_KEY not configured", 500);
  }
  if (!env.RAYGUN_MCP_URL) {
    return error("RAYGUN_MCP_URL not configured", 500);
  }

  const owner = match.groups?.owner;
  const name = match.groups?.name;
  const issueId = match.groups?.issueId;
  if (!owner || !name || !issueId) {
    return error("Owner, name, and issueId are required");
  }

  let resolved;
  try {
    resolved = await resolveInstalledRepo(env, owner, name);
    if (!resolved) {
      return error("Repository is not installed for the GitHub App", 404);
    }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    logger.error("Failed to resolve repository for Raygun issue detail", {
      error: message,
      repo_owner: owner,
      repo_name: name,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error(
      message === "GitHub App not configured" ? message : "Failed to resolve repository",
      500
    );
  }

  // Get Raygun configuration
  const repository = new RaygunConfigRepository(env.DB, env.REPO_SECRETS_ENCRYPTION_KEY);
  const service = new RaygunConfigService(repository);

  let config;
  try {
    config = await service.getConfig(resolved.repoId);
    if (!config) {
      return error("Please configure Raygun for this repository first.", 404);
    }
  } catch (e) {
    logger.error("Failed to get Raygun configuration for issue detail", {
      error: e instanceof Error ? e.message : String(e),
      repo_id: resolved.repoId,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error("Failed to retrieve Raygun configuration", 500);
  }

  // Fetch issue detail from Raygun MCP
  const mcpClient = new RaygunMCPClient(env.RAYGUN_MCP_URL);

  try {
    const issue = await mcpClient.getIssueDetail(config.applicationId, issueId);

    logger.info("raygun.issue_retrieved", {
      event: "raygun.issue_retrieved",
      repo_id: resolved.repoId,
      repo_owner: resolved.repoOwner,
      repo_name: resolved.repoName,
      issue_id: issueId,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });

    return json({
      issue,
    });
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    logger.error("Failed to get Raygun issue detail", {
      error: message,
      repo_id: resolved.repoId,
      issue_id: issueId,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    
    // Return user-friendly error message
    return error(message, 500);
  }
}

/**
 * Create a fix session for a Raygun issue.
 */
async function handleCreateRaygunFixSession(
  request: Request,
  env: Env,
  match: RegExpMatchArray,
  ctx: RequestContext
): Promise<Response> {
  if (!env.DB) {
    return error("Raygun configuration storage is not configured", 503);
  }
  if (!env.REPO_SECRETS_ENCRYPTION_KEY) {
    return error("REPO_SECRETS_ENCRYPTION_KEY not configured", 500);
  }
  if (!env.RAYGUN_MCP_URL) {
    return error("RAYGUN_MCP_URL not configured", 500);
  }

  const owner = match.groups?.owner;
  const name = match.groups?.name;
  const issueId = match.groups?.issueId;
  if (!owner || !name || !issueId) {
    return error("Owner, name, and issueId are required");
  }

  // Parse request body for user info
  const body = (await request.json()) as {
    userId?: string;
    githubLogin?: string;
    githubName?: string;
    githubEmail?: string;
    githubToken?: string;
    bitbucketUuid?: string;
    bitbucketLogin?: string;
    bitbucketDisplayName?: string;
    bitbucketEmail?: string;
    bitbucketToken?: string;
    bitbucketRefreshToken?: string;
    bitbucketTokenExpiresAt?: number;
    vcsProvider?: VCSProvider;
    model?: string;
  };

  let resolved;
  try {
    resolved = await resolveInstalledRepo(env, owner, name);
    if (!resolved) {
      return error("Repository is not installed for the GitHub App", 404);
    }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    logger.error("Failed to resolve repository for Raygun fix session", {
      error: message,
      repo_owner: owner,
      repo_name: name,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error(
      message === "GitHub App not configured" ? message : "Failed to resolve repository",
      500
    );
  }

  // Get Raygun configuration
  const repository = new RaygunConfigRepository(env.DB, env.REPO_SECRETS_ENCRYPTION_KEY);
  const service = new RaygunConfigService(repository);

  let config;
  try {
    config = await service.getConfig(resolved.repoId);
    if (!config) {
      return error("Please configure Raygun for this repository first.", 404);
    }
  } catch (e) {
    logger.error("Failed to get Raygun configuration for fix session", {
      error: e instanceof Error ? e.message : String(e),
      repo_id: resolved.repoId,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error("Failed to retrieve Raygun configuration", 500);
  }

  // Fetch detailed issue information from Raygun MCP
  const mcpClient = new RaygunMCPClient(env.RAYGUN_MCP_URL);

  let issue;
  try {
    issue = await mcpClient.getIssueDetail(config.applicationId, issueId);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    logger.error("Failed to get Raygun issue detail for fix session", {
      error: message,
      repo_id: resolved.repoId,
      issue_id: issueId,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error(message, 500);
  }

  // Validate issue data completeness
  if (!issue.errorMessage || !issue.fullStackTrace) {
    logger.error("Incomplete Raygun issue data", {
      repo_id: resolved.repoId,
      issue_id: issueId,
      has_error_message: !!issue.errorMessage,
      has_stack_trace: !!issue.fullStackTrace,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error("Incomplete issue data from Raygun", 500);
  }

  // VCS provider (default to github for backwards compatibility)
  const vcsProvider: VCSProvider = body.vcsProvider || "github";

  // User info
  const userId = body.userId || "anonymous";
  const githubLogin = body.githubLogin;
  const githubName = body.githubName;
  const githubEmail = body.githubEmail;
  let githubTokenEncrypted: string | null = null;

  // Bitbucket user info
  const bitbucketUuid = body.bitbucketUuid;
  const bitbucketLogin = body.bitbucketLogin;
  const bitbucketDisplayName = body.bitbucketDisplayName;
  const bitbucketEmail = body.bitbucketEmail;
  let bitbucketTokenEncrypted: string | null = null;
  let bitbucketRefreshTokenEncrypted: string | null = null;
  const bitbucketTokenExpiresAt = body.bitbucketTokenExpiresAt || null;

  // Encrypt tokens if provided
  if (body.githubToken && env.TOKEN_ENCRYPTION_KEY) {
    try {
      githubTokenEncrypted = await encryptToken(body.githubToken, env.TOKEN_ENCRYPTION_KEY);
    } catch (e) {
      logger.error("Failed to encrypt GitHub token", {
        error: e instanceof Error ? e : String(e),
      });
      return error("Failed to process GitHub token", 500);
    }
  }

  if (body.bitbucketToken && env.TOKEN_ENCRYPTION_KEY) {
    try {
      bitbucketTokenEncrypted = await encryptToken(body.bitbucketToken, env.TOKEN_ENCRYPTION_KEY);
      if (body.bitbucketRefreshToken) {
        bitbucketRefreshTokenEncrypted = await encryptToken(
          body.bitbucketRefreshToken,
          env.TOKEN_ENCRYPTION_KEY
        );
      }
    } catch (e) {
      logger.error("Failed to encrypt Bitbucket token", {
        error: e instanceof Error ? e : String(e),
      });
      return error("Failed to process Bitbucket token", 500);
    }
  }

  // Generate session ID
  const sessionId = generateId();

  // Get Durable Object
  const doId = env.SESSION.idFromName(sessionId);
  const stub = env.SESSION.get(doId);

  // Create session with Raygun context
  const raygunContext = {
    type: "raygun-fix" as const,
    issueId: issue.id,
    issueUrl: `https://app.raygun.com/crash-reporting/${config.applicationId}/errors/${issue.id}`,
    errorMessage: issue.errorMessage,
    fullStackTrace: issue.fullStackTrace,
    affectedFiles: issue.affectedFiles,
    occurrenceCount: issue.occurrenceCount,
    environment: issue.context.environment,
    version: issue.context.version,
    customData: issue.context.customData,
  };

  // Generate initial prompt for the agent
  const initialPrompt = `Analyze and fix the following error from Raygun:

**Error:** ${issue.errorMessage}

**Occurrences:** ${issue.occurrenceCount}

**Environment:** ${issue.context.environment}

**Version:** ${issue.context.version}

**Stack Trace:**
\`\`\`
${issue.fullStackTrace}
\`\`\`

**Affected Files:**
${issue.affectedFiles.length > 0 ? issue.affectedFiles.map(f => `- ${f}`).join('\n') : 'None identified'}

Please:
1. Analyze the error and stack trace to identify the root cause
2. Review the affected files in the repository
3. Propose a fix for the issue
4. Implement the fix and test it if possible

Raygun Issue URL: ${raygunContext.issueUrl}`;

  // Initialize session with Raygun context
  const initResponse = await stub.fetch(
    internalRequest(
      "http://internal/internal/init",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sessionName: sessionId,
          repoOwner: resolved.repoOwner,
          repoName: resolved.repoName,
          repoId: resolved.repoId,
          title: `Fix: ${issue.errorMessage.substring(0, 100)}`,
          model: body.model || "claude-haiku-4-5",
          vcsProvider,
          userId,
          githubLogin,
          githubName,
          githubEmail,
          githubTokenEncrypted,
          bitbucketUuid,
          bitbucketLogin,
          bitbucketDisplayName,
          bitbucketEmail,
          bitbucketTokenEncrypted,
          bitbucketRefreshTokenEncrypted,
          bitbucketTokenExpiresAt,
          raygunContext, // Pass Raygun context to session
          raygunApplicationId: config.applicationId, // Pass Application ID for MCP server
        }),
      },
      ctx
    )
  );

  if (!initResponse.ok) {
    logger.error("Failed to initialize Raygun fix session", {
      repo_id: resolved.repoId,
      issue_id: issueId,
      status: initResponse.status,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    return error("Failed to create fix session", 500);
  }

  // Store session in D1 index
  const now = Date.now();
  const sessionStore = new SessionIndexStore(env.DB);
  await sessionStore.create({
    id: sessionId,
    title: `Fix: ${issue.errorMessage.substring(0, 100)}`,
    repoOwner: resolved.repoOwner,
    repoName: resolved.repoName,
    model: body.model || "claude-haiku-4-5",
    vcsProvider,
    status: "created",
    createdAt: now,
    updatedAt: now,
  });

  // Send initial prompt to the session
  const promptResponse = await stub.fetch(
    internalRequest(
      "http://internal/internal/prompt",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: initialPrompt,
          authorId: userId,
          source: "web",
        }),
      },
      ctx
    )
  );

  if (!promptResponse.ok) {
    logger.error("Failed to send initial prompt to Raygun fix session", {
      session_id: sessionId,
      repo_id: resolved.repoId,
      issue_id: issueId,
      request_id: ctx.request_id,
      trace_id: ctx.trace_id,
    });
    // Session is created but prompt failed - still return success
  }

  logger.info("raygun.fix_session_created", {
    event: "raygun.fix_session_created",
    session_id: sessionId,
    repo_id: resolved.repoId,
    repo_owner: resolved.repoOwner,
    repo_name: resolved.repoName,
    issue_id: issueId,
    request_id: ctx.request_id,
    trace_id: ctx.trace_id,
  });

  return json({
    sessionId,
    status: "created",
    issueId: issue.id,
  }, 201);
}
