# Bitbucket Integration: Complete Analysis and Design Document

## Executive Summary

This document provides a comprehensive analysis of the background-agents codebase to design a complete Bitbucket Cloud integration alongside the existing GitHub integration. It maps the Bitbucket authentication, token lifecycle, repository access, commit, and PR flows against the current GitHub App + OAuth logic.

---

## 1. Architecture Overview

### 1.1 Current Dual-Identity Model

The system uses a **"Dual-Identity" Architecture**:

| Identity | GitHub Implementation | Bitbucket Equivalent | Purpose |
|----------|----------------------|---------------------|---------|
| **System ("Forge")** | GitHub App Installation Token | System Bot (App Password) | Headless Git operations (clone, push) |
| **User** | OAuth Access Token | OAuth Access Token | PR creation, repo listing (attribution) |

**Why this matters:**
- GitHub App tokens last 1 hour and are stable for long-running sessions
- Bitbucket OAuth tokens expire in 1-2 hours, making them unreliable for background agents
- Using a System Bot for git operations ensures session stability regardless of user token state

---

## 2. Component-by-Component Comparison

### 2.1 Authentication Flow

#### GitHub Flow (`packages/web/src/lib/auth.ts:44-52`)
```
User → Next.js → GitHub OAuth → Access Token (8h expiry)
                              → Refresh Token
                              → Profile (id, login, email, name)
```

**Scopes:** `read:user user:email repo`

#### Bitbucket Flow (`packages/web/src/lib/auth.ts:53-63`)
```
User → Next.js → Bitbucket OAuth → Access Token (1h expiry)
                                 → Refresh Token
                                 → Profile (uuid, username, display_name)
```

**Scopes:** `repository:write account`

| Aspect | GitHub | Bitbucket | Notes |
|--------|--------|-----------|-------|
| Token Lifetime | ~8 hours | 1 hour | Bitbucket tokens expire faster |
| User ID | Numeric (`profile.id`) | UUID (`profile.account_id`) | Different identifier formats |
| Username | `login` | `username` or `nickname` | Field naming differs |
| Email Access | Part of profile | Separate `/user/emails` endpoint | Requires additional API call |
| Refresh Token | Standard OAuth2 | Standard OAuth2 | Same behavior |

**Implementation Status:** ✅ Complete in `packages/web/src/lib/auth.ts`

---

### 2.2 Token Storage and Encryption

#### Schema (`packages/control-plane/src/session/schema.ts:41-55`)

| GitHub Fields | Bitbucket Fields | Type |
|---------------|------------------|------|
| `github_access_token_encrypted` | `bitbucket_access_token_encrypted` | TEXT |
| `github_refresh_token_encrypted` | `bitbucket_refresh_token_encrypted` | TEXT |
| `github_token_expires_at` | `bitbucket_token_expires_at` | INTEGER (ms) |
| `github_user_id` | `bitbucket_uuid` | TEXT |
| `github_login` | `bitbucket_login` | TEXT |
| `github_name` | `bitbucket_display_name` | TEXT |
| `github_email` | `bitbucket_email` | TEXT |

**Encryption:** AES-256-GCM with 96-bit IV (`packages/control-plane/src/auth/crypto.ts:36-68`)

**Implementation Status:** ✅ Complete

---

### 2.3 Token Refresh Logic

#### GitHub (`packages/control-plane/src/auth/github.ts:158-190`)
```typescript
getValidAccessToken():
  1. Check if expires_at > (now + 5 minutes buffer)
  2. If valid → decrypt and return
  3. If expiring → refresh via OAuth endpoint
  4. Update database with new tokens
```

#### Bitbucket (`packages/control-plane/src/auth/bitbucket.ts:162-190`)
```typescript
getValidAccessToken():
  1. Check if expires_at > (now + 5 minutes buffer)
  2. If valid → decrypt and return
  3. If expiring → refresh via OAuth endpoint
  4. Update database with new tokens
```

**Key Difference:** Same logic, but Bitbucket's 1-hour expiry means refresh is triggered more frequently.

**Implementation Status:** ✅ Complete

---

### 2.4 Repository Listing

#### GitHub Flow (`packages/control-plane/src/router.ts:1000-1087`)
```
GET /repos
  ↓
Check KV cache (5 min TTL)
  ↓
Generate GitHub App JWT
  ↓
Exchange for Installation Token
  ↓
GET /installation/repositories (paginated)
  ↓
Return normalized list
```

**Key Point:** Uses GitHub App installation, not user OAuth token.

#### Bitbucket Flow (REQUIRED)
```
GET /repos
  ↓
Check KV cache (5 min TTL)
  ↓
Determine user's VCS provider from session
  ↓
If Bitbucket:
  ├─ Get user's encrypted Bitbucket token from participants table
  ├─ Refresh if needed (getValidAccessToken)
  └─ GET /repositories?role=member (paginated)
  ↓
Return normalized list
```

**Key Difference:** Bitbucket uses user OAuth token (no App equivalent), so needs user context.

**Implementation Status:** ❌ NOT IMPLEMENTED - Router only handles GitHub App

**Required Changes (`packages/control-plane/src/router.ts`):**
```typescript
async function handleListRepos(request: Request, env: Env): Promise<Response> {
  // 1. Extract user session/provider from request
  const vcsProvider = request.headers.get('X-VCS-Provider') || 'github';

  if (vcsProvider === 'bitbucket') {
    // 2. Get user's Bitbucket token (from session or passed in header)
    const userToken = request.headers.get('Authorization')?.replace('Bearer ', '');

    // 3. Call Bitbucket API
    const repos = await listBitbucketRepos(userToken);
    return Response.json({ repositories: repos });
  }

  // Existing GitHub App logic...
}
```

---

### 2.5 Repository Cloning (Sandbox Startup)

#### GitHub Flow (`packages/modal-infra/src/sandbox/entrypoint.py:79-219`)
```
Sandbox starts
  ↓
Read env: GITHUB_APP_TOKEN, REPO_OWNER, REPO_NAME
  ↓
Clone: https://x-access-token:{token}@github.com/{owner}/{repo}.git
  ↓
Configure remote with auth token
  ↓
Fetch + rebase onto base branch
```

#### Bitbucket Flow (REQUIRED)
```
Sandbox starts
  ↓
Read env: VCS_PROVIDER, BITBUCKET_BOT_USERNAME, BITBUCKET_BOT_APP_PASSWORD
          (or BITBUCKET_APP_TOKEN as fallback)
  ↓
Clone: https://{bot_user}:{bot_password}@bitbucket.org/{workspace}/{repo}.git
  ↓
Configure remote with auth credentials
  ↓
Fetch + rebase onto base branch
```

**Implementation Status:** ❌ NOT IMPLEMENTED in entrypoint.py

**Required Changes (`packages/modal-infra/src/sandbox/entrypoint.py`):**

```python
def __init__(self):
    # Existing GitHub fields...
    self.github_app_token = os.environ.get("GITHUB_APP_TOKEN")

    # NEW: Bitbucket fields
    self.vcs_provider = os.environ.get("VCS_PROVIDER", "github")
    self.bitbucket_bot_username = os.environ.get("BITBUCKET_BOT_USERNAME")
    self.bitbucket_bot_app_password = os.environ.get("BITBUCKET_BOT_APP_PASSWORD")

async def perform_git_sync(self):
    if self.vcs_provider == "bitbucket":
        clone_url = self._get_bitbucket_clone_url()
    else:
        clone_url = self._get_github_clone_url()
    # ... rest of clone logic

def _get_bitbucket_clone_url(self) -> str:
    if self.bitbucket_bot_username and self.bitbucket_bot_app_password:
        return f"https://{self.bitbucket_bot_username}:{self.bitbucket_bot_app_password}@bitbucket.org/{self.repo_owner}/{self.repo_name}.git"
    return f"https://bitbucket.org/{self.repo_owner}/{self.repo_name}.git"
```

---

### 2.6 Git Push (Branch Push for PR)

#### GitHub Flow (`packages/modal-infra/src/sandbox/bridge.py:1130-1219`)
```
Control Plane sends: { type: "push", githubToken, branchName, ... }
  ↓
Sandbox resolves credentials: x-access-token:{token}
  ↓
Constructs URL: https://x-access-token:{token}@github.com/{owner}/{repo}.git
  ↓
Executes: git push {url} HEAD:refs/heads/{branch} -f
```

#### Bitbucket Flow (`packages/modal-infra/src/sandbox/bridge.py:1082-1128`)
```
Control Plane sends: { type: "push", vcsProvider: "bitbucket", ... }
  ↓
Sandbox resolves credentials:
  - PREFERRED: BITBUCKET_BOT_USERNAME + BITBUCKET_BOT_APP_PASSWORD
  - FALLBACK: x-token-auth:{bitbucketToken}
  ↓
Constructs URL: https://{user}:{token}@bitbucket.org/{workspace}/{repo}.git
  ↓
Executes: git push {url} HEAD:refs/heads/{branch} -f
```

**Implementation Status:** ✅ Complete in bridge.py (after recent changes)

---

### 2.7 Pull Request Creation

#### GitHub Flow (`packages/control-plane/src/session/durable-object.ts:2015-2141`)
```
Agent calls create-pull-request tool
  ↓
Control Plane: handleCreatePR()
  ↓
Get prompting user's encrypted GitHub token
  ↓
Generate GitHub App token for push
  ↓
Send push command to sandbox (App token)
  ↓
Wait for push_complete event
  ↓
Create PR via GitHub API (User OAuth token)
  ↓
Store artifact, broadcast to clients
```

#### Bitbucket Flow (REQUIRED)
```
Agent calls create-pull-request tool
  ↓
Control Plane: handleCreatePR()
  ↓
Check session.vcs_provider
  ↓
If Bitbucket:
  ├─ Get prompting user's Bitbucket token (refresh if needed)
  ├─ Generate push credentials (Bot or user token)
  ├─ Send push command with vcsProvider: "bitbucket"
  ├─ Wait for push_complete event
  ├─ Create PR via Bitbucket API (User OAuth token)
  └─ Store artifact, broadcast to clients
```

**Implementation Status:** ❌ NOT IMPLEMENTED - handleCreatePR is GitHub-only

**Required Changes (`packages/control-plane/src/session/durable-object.ts`):**

```typescript
private async handleCreatePR(request: Request): Promise<Response> {
  const session = this.getSession();
  const vcsProvider = session.vcs_provider || 'github';

  // Get the prompting user
  const promptingUser = await this.getPromptingUserForPR();

  if (vcsProvider === 'bitbucket') {
    // Get Bitbucket token (with refresh if needed)
    const accessToken = await getValidBitbucketAccessToken(
      {
        accessTokenEncrypted: promptingUser.user.bitbucket_access_token_encrypted,
        refreshTokenEncrypted: promptingUser.user.bitbucket_refresh_token_encrypted,
        expiresAt: promptingUser.user.bitbucket_token_expires_at,
      },
      this.env
    );

    // Get bot credentials for push (prefer bot over user token)
    const pushToken = this.env.BITBUCKET_BOT_APP_PASSWORD
      ? null  // Bridge will use env vars
      : accessToken;

    // Push with Bitbucket context
    await this.pushBranchToRemote(branchName, repoOwner, repoName, {
      vcsProvider: 'bitbucket',
      bitbucketToken: pushToken,
    });

    // Create PR via Bitbucket API
    const prResult = await createBitbucketPR(
      accessToken,
      repoOwner,  // workspace
      repoName,   // repo slug
      { title, body, sourceBranch: headBranch, destinationBranch: baseBranch }
    );

    // Store artifact...
  } else {
    // Existing GitHub logic...
  }
}
```

---

### 2.8 Git Identity (Commit Attribution)

#### GitHub (`packages/modal-infra/src/sandbox/bridge.py:464-479`)
```python
git_name = author_data.get("githubName")
git_email = author_data.get("githubEmail")
```

#### Bitbucket (`packages/modal-infra/src/sandbox/bridge.py:464-479`)
```python
if vcs_provider == "bitbucket":
    git_name = author_data.get("bitbucketDisplayName")
    git_email = author_data.get("bitbucketEmail")
```

**Implementation Status:** ✅ Complete

---

## 3. Data Flow Diagrams

### 3.1 Session Creation Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────────┐     ┌────────────┐
│   Web App   │────▶│ Control     │────▶│ Modal API       │────▶│  Sandbox   │
│             │     │ Plane       │     │                 │     │            │
└─────────────┘     └─────────────┘     └─────────────────┘     └────────────┘
      │                    │                    │                      │
      │ POST /sessions     │                    │                      │
      │ - repoOwner        │                    │                      │
      │ - repoName         │                    │                      │
      │ - vcsProvider ◄────┼── NEW FIELD        │                      │
      │ - userToken        │                    │                      │
      │                    │                    │                      │
      │                    │ Create SessionDO   │                      │
      │                    │ Store vcs_provider │                      │
      │                    │                    │                      │
      │                    │ POST /api_create_sandbox                  │
      │                    │ - vcs_provider ◄───┼── NEW FIELD          │
      │                    │ - git_token        │                      │
      │                    │                    │                      │
      │                    │                    │ Env vars:            │
      │                    │                    │ - VCS_PROVIDER       │
      │                    │                    │ - BITBUCKET_BOT_*    │
      │                    │                    │                      │
```

### 3.2 PR Creation Flow

```
GitHub Flow:                          Bitbucket Flow:
─────────────                         ───────────────
┌─────────┐                           ┌─────────┐
│ Agent   │                           │ Agent   │
│ Tool    │                           │ Tool    │
└────┬────┘                           └────┬────┘
     │ create-pull-request                 │ create-pull-request
     ▼                                     ▼
┌──────────┐                          ┌──────────┐
│ Control  │                          │ Control  │
│ Plane    │                          │ Plane    │
└────┬─────┘                          └────┬─────┘
     │                                     │
     │ 1. Generate App Token               │ 1. Get Bot credentials (or user token)
     │ 2. Send push cmd                    │ 2. Send push cmd + vcsProvider
     ▼                                     ▼
┌──────────┐                          ┌──────────┐
│ Sandbox  │                          │ Sandbox  │
│          │                          │          │
│ git push │                          │ git push │
│ @github  │                          │ @bitbucket│
└────┬─────┘                          └────┬─────┘
     │ push_complete                       │ push_complete
     ▼                                     ▼
┌──────────┐                          ┌──────────┐
│ Control  │                          │ Control  │
│ Plane    │                          │ Plane    │
│          │                          │          │
│ POST     │                          │ POST     │
│ /pulls   │ ◄─ User OAuth            │ /pullrequests │ ◄─ User OAuth
│ @GitHub  │                          │ @Bitbucket    │
└──────────┘                          └──────────┘
```

---

## 4. Gap Analysis

### 4.1 Implementation Status Summary

| Component | File | GitHub | Bitbucket | Priority |
|-----------|------|--------|-----------|----------|
| NextAuth Config | `packages/web/src/lib/auth.ts` | ✅ | ✅ | - |
| DB Schema | `packages/control-plane/src/session/schema.ts` | ✅ | ✅ | - |
| Token Encryption | `packages/control-plane/src/auth/crypto.ts` | ✅ | ✅ (shared) | - |
| Token Refresh | `packages/control-plane/src/auth/*.ts` | ✅ | ✅ | - |
| API Client | `packages/control-plane/src/auth/*.ts` | ✅ | ✅ | - |
| UI Sign-in | `packages/web/src/components/sidebar-layout.tsx` | ✅ | ✅ | - |
| **Repo Listing** | `packages/control-plane/src/router.ts` | ✅ | ❌ | **HIGH** |
| **Session Creation** | `packages/control-plane/src/router.ts` | ✅ | ⚠️ Partial | MEDIUM |
| **Sandbox Spawn** | `packages/modal-infra/src/web_api.py` | ✅ | ❌ | **HIGH** |
| **Git Clone** | `packages/modal-infra/src/sandbox/entrypoint.py` | ✅ | ❌ | **HIGH** |
| Git Push | `packages/modal-infra/src/sandbox/bridge.py` | ✅ | ✅ | - |
| Git Identity | `packages/modal-infra/src/sandbox/bridge.py` | ✅ | ✅ | - |
| **PR Creation** | `packages/control-plane/src/session/durable-object.ts` | ✅ | ❌ | **HIGH** |
| **Push Command** | `packages/control-plane/src/session/durable-object.ts` | ✅ | ❌ | **HIGH** |

### 4.2 Critical Missing Pieces

1. **Repository Listing (`/repos` endpoint):** No Bitbucket support
2. **Sandbox Creation:** No VCS provider passed to Modal, no Bitbucket clone support
3. **PR Creation:** hardcoded to GitHub API
4. **Push Command:** No `vcsProvider` field sent to sandbox

---

## 5. Required Changes

### 5.1 Control Plane Router (`packages/control-plane/src/router.ts`)

**File:** `packages/control-plane/src/router.ts`
**Lines:** 1000-1087

```typescript
// Add to handleListRepos (around line 1020)
async function handleListRepos(request: Request, env: Env): Promise<Response> {
  const vcsProvider = request.headers.get('X-VCS-Provider') || 'github';
  const userToken = request.headers.get('X-User-Token');

  if (vcsProvider === 'bitbucket') {
    if (!userToken) {
      return Response.json({ error: 'Bitbucket token required' }, { status: 401 });
    }

    try {
      const repos = await listBitbucketRepos(userToken);
      return Response.json({
        repositories: repos.map(r => ({
          id: r.uuid,
          owner: r.workspace?.slug || r.owner?.username,
          name: r.slug,
          fullName: r.full_name,
          description: r.description,
          private: r.is_private,
          defaultBranch: r.mainbranch?.name || 'main',
        })),
      });
    } catch (error) {
      return Response.json({ error: 'Failed to list Bitbucket repos' }, { status: 500 });
    }
  }

  // Existing GitHub App logic...
}
```

### 5.2 Session Creation (`packages/control-plane/src/router.ts`)

**File:** `packages/control-plane/src/router.ts`
**Lines:** 483-583

```typescript
// Add vcsProvider to session creation (around line 510)
const vcsProvider = body.vcsProvider || 'github';

// Store in session record (around line 545)
this.repository.createSession({
  ...existingFields,
  vcs_provider: vcsProvider,
});

// Pass to sandbox spawn (around line 570)
await lifecycle.spawnSandbox({
  ...existingConfig,
  vcsProvider,
  bitbucketBotUsername: env.BITBUCKET_BOT_USERNAME,
  bitbucketBotAppPassword: env.BITBUCKET_BOT_APP_PASSWORD,
});
```

### 5.3 Modal API (`packages/modal-infra/src/web_api.py`)

**File:** `packages/modal-infra/src/web_api.py`
**Lines:** 82-202

```python
@fastapi_endpoint(method="POST")
async def api_create_sandbox(request: dict, ...):
    # Add VCS provider handling (around line 127)
    vcs_provider = request.get("vcs_provider", "github")

    # Generate appropriate token based on provider
    if vcs_provider == "bitbucket":
        git_token = None  # Will use bot credentials from env
        bitbucket_bot_username = os.environ.get("BITBUCKET_BOT_USERNAME")
        bitbucket_bot_app_password = os.environ.get("BITBUCKET_BOT_APP_PASSWORD")
    else:
        git_token = generate_installation_token(...)  # Existing GitHub logic
        bitbucket_bot_username = None
        bitbucket_bot_app_password = None

    # Pass to sandbox (around line 160)
    config = SandboxConfig(
        ...existingFields,
        vcs_provider=vcs_provider,
        git_token=git_token,
        bitbucket_bot_username=bitbucket_bot_username,
        bitbucket_bot_app_password=bitbucket_bot_app_password,
    )
```

### 5.4 Sandbox Entrypoint (`packages/modal-infra/src/sandbox/entrypoint.py`)

**File:** `packages/modal-infra/src/sandbox/entrypoint.py`
**Lines:** 79-219

```python
class SandboxSupervisor:
    def __init__(self):
        # Add VCS fields (around line 65)
        self.vcs_provider = os.environ.get("VCS_PROVIDER", "github")
        self.bitbucket_bot_username = os.environ.get("BITBUCKET_BOT_USERNAME")
        self.bitbucket_bot_app_password = os.environ.get("BITBUCKET_BOT_APP_PASSWORD")

    def _get_clone_url(self) -> str:
        """Get authenticated clone URL based on VCS provider."""
        if self.vcs_provider == "bitbucket":
            if self.bitbucket_bot_username and self.bitbucket_bot_app_password:
                return f"https://{self.bitbucket_bot_username}:{self.bitbucket_bot_app_password}@bitbucket.org/{self.repo_owner}/{self.repo_name}.git"
            return f"https://bitbucket.org/{self.repo_owner}/{self.repo_name}.git"
        else:  # github
            if self.github_app_token:
                return f"https://x-access-token:{self.github_app_token}@github.com/{self.repo_owner}/{self.repo_name}.git"
            return f"https://github.com/{self.repo_owner}/{self.repo_name}.git"

    async def perform_git_sync(self):
        # Replace hardcoded GitHub URL (around line 110)
        clone_url = self._get_clone_url()
        # ... rest of clone logic unchanged
```

### 5.5 Durable Object PR Creation (`packages/control-plane/src/session/durable-object.ts`)

**File:** `packages/control-plane/src/session/durable-object.ts`
**Lines:** 2015-2141

```typescript
private async handleCreatePR(request: Request): Promise<Response> {
  const session = this.getSession();
  const vcsProvider = session.vcs_provider || 'github';

  const promptingUser = await this.getPromptingUserForPR();

  try {
    if (vcsProvider === 'bitbucket') {
      return await this.handleCreateBitbucketPR(session, promptingUser.user, body);
    } else {
      return await this.handleCreateGitHubPR(session, promptingUser.user, body);
    }
  } catch (error) {
    // Error handling...
  }
}

private async handleCreateBitbucketPR(
  session: SessionRow,
  user: ParticipantRow,
  body: { title: string; body: string; baseBranch?: string }
): Promise<Response> {
  // 1. Get valid Bitbucket token (refresh if needed)
  const accessToken = await getValidBitbucketAccessToken(
    {
      accessTokenEncrypted: user.bitbucket_access_token_encrypted!,
      refreshTokenEncrypted: user.bitbucket_refresh_token_encrypted,
      expiresAt: user.bitbucket_token_expires_at,
    },
    this.env
  );

  // 2. Get repository info
  const repoInfo = await getBitbucketRepository(
    accessToken,
    session.repo_owner,
    session.repo_name
  );

  const baseBranch = body.baseBranch || repoInfo.mainbranch?.name || 'main';
  const headBranch = generateBranchName(session.session_name || session.id);

  // 3. Push branch (using bot credentials if available)
  const pushResult = await this.pushBranchToRemote(headBranch, session.repo_owner, session.repo_name, {
    vcsProvider: 'bitbucket',
    // Bot credentials are in env, bridge will use them
  });

  if (!pushResult.success) {
    return Response.json({ error: pushResult.error }, { status: 500 });
  }

  // 4. Create PR via Bitbucket API
  const prResult = await createBitbucketPR(
    accessToken,
    session.repo_owner,  // workspace
    session.repo_name,   // repo slug
    {
      title: body.title,
      body: body.body,
      sourceBranch: headBranch,
      destinationBranch: baseBranch,
    }
  );

  // 5. Store artifact
  const artifactId = generateId();
  this.repository.createArtifact({
    id: artifactId,
    type: 'pr',
    url: prResult.links.html.href,
    metadata: JSON.stringify({
      number: prResult.id,
      state: prResult.state,
      head: headBranch,
      base: baseBranch,
    }),
    createdAt: Date.now(),
  });

  // 6. Broadcast
  this.broadcast({
    type: 'artifact_created',
    artifact: {
      id: artifactId,
      type: 'pr',
      url: prResult.links.html.href,
      prNumber: prResult.id,
    },
  });

  return Response.json({
    prNumber: prResult.id,
    prUrl: prResult.links.html.href,
    state: prResult.state,
  });
}
```

### 5.6 Push Command Update (`packages/control-plane/src/session/durable-object.ts`)

**File:** `packages/control-plane/src/session/durable-object.ts`
**Lines:** 1130-1190

```typescript
private async pushBranchToRemote(
  branchName: string,
  repoOwner: string,
  repoName: string,
  options?: {
    githubToken?: string;
    vcsProvider?: 'github' | 'bitbucket';
    bitbucketToken?: string;
  }
): Promise<{ success: true } | { success: false; error: string }> {
  // ... existing setup code ...

  // Tell sandbox to push with VCS context
  this.safeSend(sandboxWs, {
    type: 'push',
    branchName,
    repoOwner,
    repoName,
    vcsProvider: options?.vcsProvider || 'github',
    githubToken: options?.githubToken,
    bitbucketToken: options?.bitbucketToken,
  });

  // ... rest of method unchanged ...
}
```

---

## 6. Environment Variables

### 6.1 Required Bitbucket Variables

| Variable | Location | Description |
|----------|----------|-------------|
| `BITBUCKET_CLIENT_ID` | Web App | OAuth Consumer Key |
| `BITBUCKET_CLIENT_SECRET` | Web App | OAuth Consumer Secret |
| `BITBUCKET_BOT_USERNAME` | Control Plane + Modal | System Bot account username |
| `BITBUCKET_BOT_APP_PASSWORD` | Control Plane + Modal | System Bot app password |

### 6.2 Terraform Configuration

Add to `terraform/environments/production/main.tf`:

```hcl
# Control Plane Worker
module "control_plane_worker" {
  # ... existing config ...

  secrets = {
    # ... existing secrets ...
    BITBUCKET_BOT_USERNAME     = var.bitbucket_bot_username
    BITBUCKET_BOT_APP_PASSWORD = var.bitbucket_bot_app_password
  }
}

# Modal App
module "modal_app" {
  # ... existing config ...

  secrets = {
    # ... existing secrets ...
    BITBUCKET_BOT_USERNAME     = var.bitbucket_bot_username
    BITBUCKET_BOT_APP_PASSWORD = var.bitbucket_bot_app_password
  }
}
```

---

## 7. Testing Plan

### 7.1 Unit Tests

| Test | File | Description |
|------|------|-------------|
| `bitbucket-api.test.ts` | `packages/control-plane/src/auth/__tests__/` | Mock Bitbucket API responses |
| `token-refresh.test.ts` | `packages/control-plane/src/auth/__tests__/` | Test 1-hour expiry handling |
| `pr-creation.test.ts` | `packages/control-plane/src/auth/__tests__/` | Verify Bitbucket PR payload structure |

### 7.2 Integration Tests

#### 7.2.1 Authentication Flow
```bash
# 1. Login with Bitbucket
open http://localhost:3000/api/auth/signin

# 2. Verify token storage
sqlite3 .wrangler/state/d1/DB/db.sqlite \
  "SELECT bitbucket_uuid, bitbucket_login,
          length(bitbucket_access_token_encrypted) as token_len
   FROM participants
   WHERE vcs_provider = 'bitbucket'"
```

#### 7.2.2 Repository Listing
```bash
# Test Bitbucket repo listing
curl -X GET "https://control-plane.example.com/repos" \
  -H "X-VCS-Provider: bitbucket" \
  -H "X-User-Token: ${BITBUCKET_ACCESS_TOKEN}"
```

#### 7.2.3 Session Creation
```bash
# Create Bitbucket session
curl -X POST "https://control-plane.example.com/sessions" \
  -H "Content-Type: application/json" \
  -d '{
    "repoOwner": "my-workspace",
    "repoName": "my-repo",
    "vcsProvider": "bitbucket"
  }'
```

### 7.3 End-to-End Manual Verification

#### Test Case 1: Basic Authentication
1. Navigate to app, click "Sign in with Bitbucket"
2. Authorize OAuth scopes (`repository:write account`)
3. **Verify:** User lands on dashboard, sees Bitbucket avatar
4. **DB Check:** `participants` has `bitbucket_*` fields populated

#### Test Case 2: Repository Listing
1. Sign in with Bitbucket
2. Click "New Session"
3. **Verify:** Repository dropdown shows Bitbucket repos
4. **Verify:** Repos show workspace/slug format

#### Test Case 3: Session Creation + Clone
1. Select a Bitbucket repository
2. Create new session
3. **Verify:** Session starts, shows "Cloning repository..."
4. **Verify:** Modal logs show `bitbucket.org` clone URL
5. **Verify:** Clone uses bot credentials (not user token)

#### Test Case 4: Prompt Execution
1. In Bitbucket session, send prompt: "Create a file hello.txt with 'Hello World'"
2. **Verify:** Agent creates file
3. **Verify:** `git log` shows commit attributed to user (correct email)

#### Test Case 5: PR Creation
1. Send prompt: "Create a PR with the changes"
2. **Verify:** Agent calls `create-pull-request` tool
3. **Verify:** Branch pushed to Bitbucket (check repo branches)
4. **Verify:** PR created in Bitbucket UI
5. **Verify:** PR author is the user (not bot)
6. **Verify:** Branch commits show bot as pusher (if using bot)

#### Test Case 6: Token Refresh
1. Start long session (>1 hour)
2. After token expires, request PR creation
3. **Verify:** Token refreshes automatically
4. **Verify:** PR creation succeeds without re-auth

### 7.4 Failure Case Testing

| Scenario | Expected Behavior |
|----------|-------------------|
| Invalid Bitbucket OAuth token | 401 error, prompt to re-authenticate |
| Bot credentials missing | Fallback to user OAuth token for push |
| Token refresh fails | Clear error message, prompt to sign in again |
| Private repo without access | Clear error during clone |
| PR to protected branch | Bitbucket returns 400, shown to user |
| Rate limiting | Retry with backoff, error after max retries |

### 7.5 Cross-Provider Verification

1. Sign in with GitHub, create session
2. Sign out, sign in with Bitbucket
3. **Verify:** Previous GitHub session still accessible
4. **Verify:** New session uses Bitbucket
5. **Verify:** Both sessions function correctly

---

## 8. Rollout Plan

### Phase 1: Backend Infrastructure (Week 1)
- [ ] Add Bitbucket env vars to Terraform
- [ ] Update Modal API to pass VCS provider
- [ ] Update entrypoint.py for Bitbucket clone
- [ ] Deploy to staging

### Phase 2: Repository Listing (Week 1)
- [ ] Update router.ts for Bitbucket repos
- [ ] Update web app to pass VCS provider header
- [ ] Test repo listing E2E

### Phase 3: PR Creation (Week 2)
- [ ] Update durable-object.ts for Bitbucket PR
- [ ] Update push command to include vcsProvider
- [ ] Test PR creation E2E

### Phase 4: Testing & Hardening (Week 2)
- [ ] Run full E2E test suite
- [ ] Test failure scenarios
- [ ] Performance testing
- [ ] Documentation update

### Phase 5: Production Rollout (Week 3)
- [ ] Feature flag for Bitbucket provider
- [ ] Gradual rollout (10% → 50% → 100%)
- [ ] Monitor error rates
- [ ] Full GA

---

## 9. Appendix

### 9.1 Bitbucket API Reference

| Operation | Endpoint | Auth |
|-----------|----------|------|
| List Repos | `GET /2.0/repositories?role=member` | User OAuth |
| Get Repo | `GET /2.0/repositories/{workspace}/{repo_slug}` | User OAuth |
| Create PR | `POST /2.0/repositories/{workspace}/{repo_slug}/pullrequests` | User OAuth |
| Get User | `GET /2.0/user` | User OAuth |
| Get Emails | `GET /2.0/user/emails` | User OAuth |
| Git Clone | `https://{user}:{password}@bitbucket.org/{workspace}/{repo}.git` | Bot App Password |

### 9.2 Key File Locations

| Component | Path |
|-----------|------|
| NextAuth Config | `packages/web/src/lib/auth.ts` |
| Bitbucket API Client | `packages/control-plane/src/auth/bitbucket.ts` |
| Token Encryption | `packages/control-plane/src/auth/crypto.ts` |
| Session Schema | `packages/control-plane/src/session/schema.ts` |
| Durable Object | `packages/control-plane/src/session/durable-object.ts` |
| Router | `packages/control-plane/src/router.ts` |
| Modal Web API | `packages/modal-infra/src/web_api.py` |
| Sandbox Entrypoint | `packages/modal-infra/src/sandbox/entrypoint.py` |
| Sandbox Bridge | `packages/modal-infra/src/sandbox/bridge.py` |
