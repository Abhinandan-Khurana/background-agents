### **Bitbucket Integration Implementation Plan**

---

## 1. Executive Summary

This specification integrates Bitbucket Cloud as a first-class Version Control System (VCS) alongside GitHub. It adheres to the existing **"Dual-Identity" Architecture**:

1. **"The Forge" (System Identity):** Handles high-privilege, headless Git operations (Cloning, Pushing Agent Branches). On GitHub, this is the "App Installation Token". On Bitbucket, this will be a **System Bot Account (App Password)** to ensure stability and avoid user-token expiry during long agent sessions.
2. **"The User" (OAuth Identity):** Handles attribution and permissions. Used solely to open Pull Requests as the actual user and list repositories they have access to.

---

## 2. Architecture & Data Flow

### 2.1 System Context Diagram

```mermaid
graph TD
    User[User / Browser] -->|1. OAuth Login| NextAuth[NextAuth.js]
    User -->|2. Create Session| CP[Control Plane (Worker)]
    
    subgraph "Auth Layer"
        NextAuth -->|Exchanges Code| BB_Auth[Bitbucket OAuth]
        CP -->|Stores Tokens| DB[(D1 Database)]
    end
    
    subgraph "Session Layer"
        CP -->|Spawns| DO[Durable Object]
        DO -->|Orchestrates| SB[Sandbox (Modal)]
    end
    
    subgraph "Bitbucket Cloud"
        BB_API[Bitbucket API]
        BB_Git[Bitbucket Git Host]
    end
    
    DO -->|3. API: Create PR| BB_API
    SB -->|4. Git: Clone/Push| BB_Git

```

### 2.2 Token Strategy & Lifecycle

| Token Type | Source | Storage | Usage | Refresh Policy |
| --- | --- | --- | --- | --- |
| **User Access Token** | OAuth 2.0 (Auth Code) | Encrypted in `participants` table | API: List Repos, Create PRs | Refresh via Refresh Token on 401 |
| **User Refresh Token** | OAuth 2.0 | Encrypted in `participants` table | Generating new Access Tokens | Rotated on use |
| **Forge (Bot) Creds** | Env Vars (`BITBUCKET_APP_PASSWORD`) | `wrangler.toml` / Env | Git: Clone, Branch, Push | Static (Rotated manually) |

> **Why a Bot Account for Git?**
> Unlike GitHub Apps, Bitbucket OAuth tokens have short lifespans (1-2 hours). If a background agent runs for 3 hours, a user token used for `git push` inside the Sandbox will expire, causing the agent to fail. Using a System Bot (App Password) for the *working branch* guarantees session stability. The *PR* is still opened by the User using their OAuth token.

---

## 3. Database Schema Changes

We will extend the schema to support the `vcs_provider` discriminator and Bitbucket-specific credentials.

### `packages/control-plane/src/session/schema.ts`

```sql
-- 1. Add VCS Provider discriminator (Migration 00X)
ALTER TABLE participants ADD COLUMN vcs_provider TEXT DEFAULT 'github'; -- 'github' | 'bitbucket'
ALTER TABLE session ADD COLUMN vcs_provider TEXT DEFAULT 'github';

-- 2. Add Bitbucket OAuth fields to Participants
ALTER TABLE participants ADD COLUMN bitbucket_access_token_encrypted TEXT;
ALTER TABLE participants ADD COLUMN bitbucket_refresh_token_encrypted TEXT;
ALTER TABLE participants ADD COLUMN bitbucket_token_expires_at INTEGER; -- Unix Timestamp

-- 3. Add Workspace context (Bitbucket specific) to Session
-- GitHub uses 'owner', Bitbucket uses 'workspace'. We can map 'workspace' to 'repo_owner' column,
-- but explicit typing in code is safer.

```

---

## 4. Implementation Specifications

### 4.1 Phase 1: Authentication (Control Plane & Web)

**Goal:** Allow users to link Bitbucket accounts and store tokens securely.

#### **A. Environment Variables**

Add to `.env` and `wrangler.toml`:

```toml
# Bitbucket OAuth Consumer
BITBUCKET_CLIENT_ID="<key>"
BITBUCKET_CLIENT_SECRET="<secret>"

# Bitbucket Forge (Bot Account) for Git Operations
BITBUCKET_BOT_USERNAME="background-agent-bot"
BITBUCKET_BOT_APP_PASSWORD="<app-password>"

```

#### **B. NextAuth Config (`packages/web/src/auth/options.ts`)**

Configure the provider. Bitbucket requires specific scopes to read repos and write PRs.

```typescript
import BitbucketProvider from "next-auth/providers/bitbucket";

export const authOptions: AuthOptions = {
  providers: [
    BitbucketProvider({
      clientId: process.env.BITBUCKET_CLIENT_ID!,
      clientSecret: process.env.BITBUCKET_CLIENT_SECRET!,
      authorization: {
        params: {
          // repository:write - needed to create PRs (Bitbucket weirdness: PRs are part of repo write)
          // account - needed for user profile
          scope: "repository:write account", 
        },
      },
    }),
    // ... GitHub config
  ],
  callbacks: {
    async jwt({ token, account }) {
      if (account?.provider === "bitbucket") {
        token.provider = "bitbucket";
        token.accessToken = account.access_token;
        token.refreshToken = account.refresh_token;
        token.expiresAt = account.expires_at; // Ensure we capture expiry
      }
      return token;
    },
    // ...
  }
};

```

### 4.2 Phase 2: Control Plane Logic

**Goal:** Handle API requests for Bitbucket resources.

#### **A. Bitbucket API Client (`packages/control-plane/src/auth/bitbucket.ts`)**

We need a dedicated client to handle Bitbucket's JSON structure, which differs from GitHub's.

```typescript
const BB_API_BASE = "https://api.bitbucket.org/2.0";

export async function createBitbucketPR(
  token: string,
  workspace: string,
  repoSlug: string,
  pr: { title: string; sourceBranch: string; destinationBranch: string; body: string }
) {
  const response = await fetch(`${BB_API_BASE}/repositories/${workspace}/${repoSlug}/pullrequests`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      title: pr.title,
      description: pr.body,
      source: { branch: { name: pr.sourceBranch } },
      destination: { branch: { name: pr.destinationBranch } },
      close_source_branch: true
    }),
  });

  if (!response.ok) throw new Error(`Bitbucket PR failed: ${response.statusText}`);
  return response.json();
}

```

#### **B. Token Refresh Logic**

Bitbucket tokens expire quickly (1 hour). The Durable Object must check expiry before attempting PR creation.

```typescript
// Helper in packages/control-plane/src/auth/token-management.ts
export async function getValidBitbucketToken(participant: Participant, env: Env): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  
  // If token is valid for at least 5 more minutes, return it
  if (participant.bitbucket_token_expires_at && participant.bitbucket_token_expires_at > now + 300) {
    return decryptToken(participant.bitbucket_access_token_encrypted, env.ENCRYPTION_KEY);
  }

  // Otherwise, refresh
  const refreshToken = await decryptToken(participant.bitbucket_refresh_token_encrypted, env.ENCRYPTION_KEY);
  const newTokens = await refreshBitbucketOAuth(refreshToken, env.BITBUCKET_CLIENT_ID, env.BITBUCKET_CLIENT_SECRET);

  // Update DB (Side effect)
  await updateParticipantTokens(participant.id, newTokens);

  return newTokens.access_token;
}

```

### 4.3 Phase 3: Sandbox Bridge (Python)

**Goal:** Teach the Python bridge how to speak "Bitbucket".

#### **A. Update `bridge.py**`

The bridge needs to construct the remote URL differently. Bitbucket URLs format: `https://<user>:<token>@bitbucket.org/<workspace>/<repo>.git`

```python
# packages/modal-infra/src/sandbox/bridge.py

def _get_git_remote_url(self, cmd: dict, token: str, user: str) -> str:
    provider = cmd.get("vcsProvider", "github")
    owner = cmd.get("repoOwner")
    name = cmd.get("repoName")

    if provider == "bitbucket":
        # Bitbucket requires the username in the auth URL string for App Passwords usually
        # Format: https://username:password@bitbucket.org/workspace/repo.git
        return f"https://{user}:{token}@bitbucket.org/{owner}/{name}.git"
    
    # Default to GitHub
    return f"https://x-access-token:{token}@github.com/{owner}/{name}.git"

async def _resolve_vcs_creds(self, cmd: dict) -> tuple[str, str]:
    """Returns (username, password/token)"""
    if cmd.get("vcsProvider") == "bitbucket":
        # PREFERRED: Use System Bot for stability
        if os.environ.get("BITBUCKET_BOT_APP_PASSWORD"):
             return (os.environ["BITBUCKET_BOT_USERNAME"], os.environ["BITBUCKET_BOT_APP_PASSWORD"])
        # FALLBACK: Use User Token (Risk of expiry)
        return ("x-token-auth", cmd.get("bitbucketToken"))
        
    # GitHub Logic...
    return ("x-access-token", cmd.get("githubToken"))

```

---

## 5. Sequence Diagrams

### 5.1 Orchestration: Creating a Bitbucket PR

This flow demonstrates the hand-off between the System Identity (Git Push) and User Identity (Create PR).

```mermaid
sequenceDiagram
    participant DO as Durable Object
    participant DB as Database
    participant SB as Sandbox (Python)
    participant BB as Bitbucket API

    Note over DO: User requests "Create PR"
    
    DO->>SB: Send Command: PUSH_BRANCH
    Note right of DO: Includes Repo Info + VCS Provider
    
    SB->>SB: Authenticate using BITBUCKET_BOT_APP_PASSWORD
    SB->>BB: git push origin agent-branch
    BB-->>SB: Success
    SB-->>DO: Push Complete
    
    DO->>DB: Retrieve User's Bitbucket OAuth Token
    DO->>DO: Validate/Refresh Token
    
    DO->>BB: POST /repositories/{workspace}/{repo}/pullrequests
    Note right of DO: Auth: Bearer <User_OAuth_Token>
    
    BB-->>DO: 201 Created (PR JSON)
    DO->>DO: Save Artifact (PR Link)

```

---

## 6. Security & Safety Checklist

1. **Scope Minimization:**
* Do **not** request `repository:admin`. Only `repository:write` is needed for PRs.
* Ensure the Bot App Password has specific permissions (Repositories: Write), not Admin.


2. **Token Encryption:**
* Re-use the existing `encryptToken` / `decryptToken` primitives (`crypto.ts`) for Bitbucket tokens. Never store plain text.


3. **Boundary Checks:**
* Ensure the API explicitly checks `vcs_provider`. Don't assume a session with a `repo_owner` implies GitHub.


4. **Logging:**
* **Redaction:** Update logger to specifically redact `bitbucket_access_token` and `refresh_token` in logs.



---

## 7. Testing Strategy

### 7.1 Unit Tests (Jest)

* **`bitbucket.test.ts`:** Mock `fetch` to verify the payload structure matches Bitbucket API docs exactly (especially the nested `source: { branch: ... }` object).
* **`token-management.test.ts`:** Simulate an expired token and verify `refreshBitbucketOAuth` is called.

### 7.2 Integration Tests

* **Repo Listing:** Verify `handleListRepos` returns a normalized list of repositories when `provider=bitbucket` is passed.
* **Session Init:** Verify `handleInit` correctly stores `vcs_provider='bitbucket'` in the DB.

### 7.3 Manual Verification Plan

1. **Auth:** Log in with Bitbucket. Check DB `participants` table for encrypted tokens.
2. **Listing:** Check the "New Session" UI to ensure Bitbucket repos appear.
3. **The Agent Loop:**
* Start Session on a Bitbucket repo.
* Ask Agent to "Create a file named hello.txt".
* Check Bitbucket UI: Ensure branch `agent-xxx` exists and was pushed by the Bot Account.
* Ask Agent to "Create PR".
* Check Bitbucket UI: Ensure PR exists and is attributed to the **User** (via OAuth), not the Bot.



---

## 8. Development Next Steps

1. **Apply DB Migrations:** Run SQL to add `vcs_provider` and token columns.
2. **Install SDKs:** Add `next-auth/providers/bitbucket`.
3. **Implement Web Auth:** Update `sidebar-layout.tsx` and `auth/options.ts`.
4. **Implement Control Plane:** Create `auth/bitbucket.ts` and update `durable-object.ts`.
5. **Update Sandbox:** Deploy new `bridge.py` image with Bitbucket URL logic.
6. **Verify:** Run the Manual Verification Plan.
