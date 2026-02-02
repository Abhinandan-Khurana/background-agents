/**
 * Bitbucket authentication utilities.
 */

import { decryptToken, encryptToken } from "./crypto";
import type { BitbucketUser, BitbucketTokenResponse } from "../types";

/**
 * Bitbucket OAuth configuration.
 */
export interface BitbucketOAuthConfig {
  clientId: string;
  clientSecret: string;
  encryptionKey: string;
}

/**
 * Bitbucket token with metadata.
 */
export interface StoredBitbucketToken {
  accessTokenEncrypted: string;
  refreshTokenEncrypted: string;
  expiresAt: number;
  scopes: string;
}

const BB_API_BASE = "https://api.bitbucket.org/2.0";
const BB_OAUTH_BASE = "https://bitbucket.org/site/oauth2";

/**
 * Exchange authorization code for tokens.
 */
export async function exchangeCodeForToken(
  code: string,
  config: BitbucketOAuthConfig
): Promise<BitbucketTokenResponse> {
  const response = await fetch(`${BB_OAUTH_BASE}/access_token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${btoa(`${config.clientId}:${config.clientSecret}`)}`,
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
    }),
  });

  const data = (await response.json()) as BitbucketTokenResponse & {
    error?: string;
    error_description?: string;
  };

  if ("error" in data && data.error) {
    throw new Error(data.error_description ?? data.error);
  }

  return data;
}

/**
 * Refresh an expired access token.
 * Bitbucket tokens expire after 1 hour (3600 seconds).
 */
export async function refreshAccessToken(
  refreshToken: string,
  config: BitbucketOAuthConfig
): Promise<BitbucketTokenResponse> {
  const response = await fetch(`${BB_OAUTH_BASE}/access_token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${btoa(`${config.clientId}:${config.clientSecret}`)}`,
    },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    }),
  });

  const data = (await response.json()) as BitbucketTokenResponse & {
    error?: string;
    error_description?: string;
  };

  if ("error" in data && data.error) {
    throw new Error(data.error_description ?? data.error);
  }

  return data;
}

/**
 * Get current user info from Bitbucket.
 */
export async function getBitbucketUser(accessToken: string): Promise<BitbucketUser> {
  const response = await fetch(`${BB_API_BASE}/user`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`Bitbucket API error: ${response.status}`);
  }

  return response.json() as Promise<BitbucketUser>;
}

/**
 * Get user's email addresses from Bitbucket.
 * Note: Requires 'email' scope which is not included by default.
 */
export async function getBitbucketUserEmails(
  accessToken: string
): Promise<Array<{ email: string; is_primary: boolean; is_confirmed: boolean }>> {
  const response = await fetch(`${BB_API_BASE}/user/emails`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    // Email scope may not be granted, return empty array
    if (response.status === 403) {
      return [];
    }
    throw new Error(`Bitbucket API error: ${response.status}`);
  }

  const data = await response.json() as { values: Array<{ email: string; is_primary: boolean; is_confirmed: boolean }> };
  return data.values ?? [];
}

/**
 * Store encrypted Bitbucket tokens.
 */
export async function encryptBitbucketTokens(
  tokens: BitbucketTokenResponse,
  encryptionKey: string
): Promise<StoredBitbucketToken> {
  const accessTokenEncrypted = await encryptToken(tokens.access_token, encryptionKey);
  const refreshTokenEncrypted = await encryptToken(tokens.refresh_token, encryptionKey);

  // expires_in is in seconds, convert to milliseconds timestamp
  const expiresAt = Date.now() + tokens.expires_in * 1000;

  return {
    accessTokenEncrypted,
    refreshTokenEncrypted,
    expiresAt,
    scopes: tokens.scopes,
  };
}

/**
 * Get valid access token, refreshing if necessary.
 * Bitbucket tokens expire after 1 hour, so we refresh if less than 5 minutes remain.
 */
export async function getValidAccessToken(
  stored: StoredBitbucketToken,
  config: BitbucketOAuthConfig
): Promise<{ accessToken: string; refreshed: boolean; newStored?: StoredBitbucketToken }> {
  const now = Date.now();
  const bufferMs = 5 * 60 * 1000; // 5 minutes

  // Check if token needs refresh
  if (stored.expiresAt - now < bufferMs) {
    const refreshToken = await decryptToken(stored.refreshTokenEncrypted, config.encryptionKey);

    const newTokens = await refreshAccessToken(refreshToken, config);
    const newStored = await encryptBitbucketTokens(newTokens, config.encryptionKey);

    return {
      accessToken: newTokens.access_token,
      refreshed: true,
      newStored,
    };
  }

  // Token is still valid
  const accessToken = await decryptToken(stored.accessTokenEncrypted, config.encryptionKey);

  return {
    accessToken,
    refreshed: false,
  };
}

/**
 * Get valid access token for PR creation, handling refresh and database updates.
 * This is a convenience wrapper for use in durable objects.
 *
 * @param tokenInfo - Token information from participant record
 * @param env - Environment with OAuth credentials
 * @param participantId - Participant ID for updating tokens in database
 * @param repository - Repository for updating participant tokens
 * @returns Plain access token string
 */
export async function getValidAccessTokenForPR(
  tokenInfo: {
    accessTokenEncrypted: string;
    refreshTokenEncrypted: string | null;
    expiresAt: number | null;
  },
  env: {
    BITBUCKET_CLIENT_ID?: string;
    BITBUCKET_CLIENT_SECRET?: string;
    TOKEN_ENCRYPTION_KEY: string;
  },
  participantId?: string,
  repository?: { updateParticipantBitbucketTokens?: (id: string, tokens: StoredBitbucketToken) => void }
): Promise<string> {
  const now = Date.now();
  const bufferMs = 5 * 60 * 1000; // 5 minutes

  // If token is still valid (with buffer), just decrypt and return
  if (tokenInfo.expiresAt && (tokenInfo.expiresAt - now > bufferMs)) {
    return await decryptToken(tokenInfo.accessTokenEncrypted, env.TOKEN_ENCRYPTION_KEY);
  }

  // Token needs refresh
  if (!tokenInfo.refreshTokenEncrypted) {
    // No refresh token, try using existing token (might fail)
    return await decryptToken(tokenInfo.accessTokenEncrypted, env.TOKEN_ENCRYPTION_KEY);
  }

  if (!env.BITBUCKET_CLIENT_ID || !env.BITBUCKET_CLIENT_SECRET) {
    // OAuth not configured, try using existing token
    return await decryptToken(tokenInfo.accessTokenEncrypted, env.TOKEN_ENCRYPTION_KEY);
  }

  // Refresh the token
  const refreshToken = await decryptToken(tokenInfo.refreshTokenEncrypted, env.TOKEN_ENCRYPTION_KEY);
  const config: BitbucketOAuthConfig = {
    clientId: env.BITBUCKET_CLIENT_ID,
    clientSecret: env.BITBUCKET_CLIENT_SECRET,
    encryptionKey: env.TOKEN_ENCRYPTION_KEY,
  };

  try {
    const newTokens = await refreshAccessToken(refreshToken, config);
    const newStored = await encryptBitbucketTokens(newTokens, env.TOKEN_ENCRYPTION_KEY);

    // Update participant record if repository provided
    if (participantId && repository?.updateParticipantBitbucketTokens) {
      repository.updateParticipantBitbucketTokens(participantId, newStored);
    }

    return newTokens.access_token;
  } catch (error) {
    // Refresh failed, try using existing token
    return await decryptToken(tokenInfo.accessTokenEncrypted, env.TOKEN_ENCRYPTION_KEY);
  }
}

/**
 * Create a pull request via Bitbucket API.
 */
export async function createBitbucketPR(
  token: string,
  workspace: string,
  repoSlug: string,
  pr: {
    title: string;
    sourceBranch: string;
    destinationBranch: string;
    body: string;
    closeSourceBranch?: boolean;
  }
): Promise<{
  id: number;
  title: string;
  state?: string;
  links: {
    html: { href: string };
  };
}> {
  const response = await fetch(
    `${BB_API_BASE}/repositories/${workspace}/${repoSlug}/pullrequests`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        title: pr.title,
        description: pr.body,
        source: {
          branch: {
            name: pr.sourceBranch,
          },
        },
        destination: {
          branch: {
            name: pr.destinationBranch,
          },
        },
        close_source_branch: pr.closeSourceBranch ?? true,
      }),
    }
  );

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Bitbucket PR creation failed: ${response.status} - ${error}`);
  }

  return response.json() as Promise<{
    id: number;
    title: string;
    links: {
      html: { href: string };
    };
  }>;
}

/**
 * List repositories accessible to the user.
 */
export async function listBitbucketRepos(
  token: string,
  options: { page?: number; pagelen?: number } = {}
): Promise<
  Array<{
    uuid: string;
    full_name: string;
    name: string;
    slug: string;
    workspace: { slug: string };
    links: {
      html: { href: string };
    };
  }>
> {
  const { page = 1, pagelen = 100 } = options;

  const response = await fetch(
    `${BB_API_BASE}/repositories?role=member&page=${page}&pagelen=${pagelen}`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
      },
    }
  );

  if (!response.ok) {
    throw new Error(`Bitbucket API error: ${response.status}`);
  }

  const data = await response.json() as {
    values: Array<{
      uuid: string;
      full_name: string;
      name: string;
      slug: string;
      workspace: { slug: string };
      links: {
        html: { href: string };
      };
    }>;
  };

  return data.values ?? [];
}

/**
 * Get repository information.
 */
export async function getBitbucketRepository(
  token: string,
  workspace: string,
  repoSlug: string
): Promise<{
  uuid: string;
  full_name: string;
  name: string;
  slug: string;
  mainbranch: { name: string } | null;
  workspace: { slug: string };
}> {
  const response = await fetch(
    `${BB_API_BASE}/repositories/${workspace}/${repoSlug}`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
      },
    }
  );

  if (!response.ok) {
    throw new Error(`Bitbucket API error: ${response.status}`);
  }

  return response.json() as Promise<{
    uuid: string;
    full_name: string;
    name: string;
    slug: string;
    mainbranch: { name: string } | null;
    workspace: { slug: string };
  }>;
}

/**
 * Generate a git commit email for Bitbucket user.
 * Uses Atlassian account ID format.
 */
export function generateBitbucketNoreplyEmail(bitbucketUser: BitbucketUser): string {
  // Bitbucket uses account_id as the stable identifier
  return `${bitbucketUser.account_id}@bitbucket.org`;
}

/**
 * Get best email for git commit attribution.
 */
export function getCommitEmail(
  bitbucketUser: BitbucketUser,
  emails?: Array<{ email: string; is_primary: boolean; is_confirmed: boolean }>
): string {
  // Use primary confirmed email if available
  if (emails) {
    const primary = emails.find((e) => e.is_primary && e.is_confirmed);
    if (primary) {
      return primary.email;
    }
  }

  // Fall back to noreply format
  return generateBitbucketNoreplyEmail(bitbucketUser);
}
