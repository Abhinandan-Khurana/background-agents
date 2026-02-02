import type { NextAuthOptions } from "next-auth";
import GitHubProvider from "next-auth/providers/github";
import BitbucketProvider from "next-auth/providers/bitbucket";
import { checkAccessAllowed, parseAllowlist } from "./access-control";

// VCS Provider type
export type VCSProvider = "github" | "bitbucket";

// Extend NextAuth types to include provider-specific user info
declare module "next-auth" {
  interface Session {
    accessToken?: string;
    accessTokenExpiresAt?: number; // Unix timestamp in milliseconds
    provider?: VCSProvider;
    user: {
      id?: string; // Provider user ID
      login?: string; // Provider username
      name?: string | null;
      email?: string | null;
      image?: string | null;
    };
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    accessToken?: string;
    refreshToken?: string;
    accessTokenExpiresAt?: number; // Unix timestamp in milliseconds
    provider?: VCSProvider;
    // GitHub-specific
    githubUserId?: string;
    githubLogin?: string;
    // Bitbucket-specific
    bitbucketUuid?: string;
    bitbucketLogin?: string;
    bitbucketDisplayName?: string;
  }
}

export const authOptions: NextAuthOptions = {
  debug: process.env.NODE_ENV === "development" || process.env.NEXTAUTH_DEBUG === "true",
  providers: [
    GitHubProvider({
      clientId: process.env.GITHUB_CLIENT_ID!,
      clientSecret: process.env.GITHUB_CLIENT_SECRET!,
      authorization: {
        params: {
          scope: "read:user user:email repo",
        },
      },
    }),
    BitbucketProvider({
      clientId: process.env.BITBUCKET_CLIENT_ID!,
      clientSecret: process.env.BITBUCKET_CLIENT_SECRET!,
      authorization: {
        params: {
          // repository:write - needed to create PRs
          // account - needed for user profile
          scope: "repository:write account",
        },
      },
    }),
  ],
  callbacks: {
    async signIn({ profile, user, account }) {
      const config = {
        allowedDomains: parseAllowlist(process.env.ALLOWED_EMAIL_DOMAINS),
        allowedUsers: parseAllowlist(process.env.ALLOWED_USERS),
      };

      if (account?.provider === "github") {
        const githubProfile = profile as { login?: string };
        const isAllowed = checkAccessAllowed(config, {
          githubUsername: githubProfile.login,
          email: user.email ?? undefined,
        });
        return isAllowed;
      }

      if (account?.provider === "bitbucket") {
        // For Bitbucket, we check by username/login or email
        const bitbucketProfile = profile as { username?: string; display_name?: string };
        const isAllowed = checkAccessAllowed(config, {
          githubUsername: bitbucketProfile.username, // Reuse field for bitbucket username
          email: user.email ?? undefined,
        });
        return isAllowed;
      }

      return false;
    },
    async jwt({ token, account, profile }) {
      if (account) {
        token.accessToken = account.access_token;
        token.refreshToken = account.refresh_token;

        if (account.provider === "github") {
          token.provider = "github";
          // GitHub OAuth tokens expire after 8 hours
          // expires_at is in seconds, convert to milliseconds
          if (account.expires_at) {
            token.accessTokenExpiresAt = account.expires_at * 1000;
          } else {
            // Default to 8 hours from now if not provided
            token.accessTokenExpiresAt = Date.now() + 8 * 60 * 60 * 1000;
          }
        } else if (account.provider === "bitbucket") {
          token.provider = "bitbucket";
          // Bitbucket tokens expire after 1 hour (3600 seconds)
          if (account.expires_at) {
            token.accessTokenExpiresAt = account.expires_at * 1000;
          } else {
            // Default to 1 hour from now if not provided
            token.accessTokenExpiresAt = Date.now() + 60 * 60 * 1000;
          }
        }
      }

      if (profile) {
        if (token.provider === "github") {
          // GitHub profile includes id (numeric) and login (username)
          const githubProfile = profile as { id?: number; login?: string };
          if (githubProfile.id) {
            token.githubUserId = githubProfile.id.toString();
          }
          if (githubProfile.login) {
            token.githubLogin = githubProfile.login;
          }
        } else if (token.provider === "bitbucket") {
          // Bitbucket profile includes uuid and username
          const bitbucketProfile = profile as {
            uuid?: string;
            username?: string;
            display_name?: string;
          };
          if (bitbucketProfile.uuid) {
            token.bitbucketUuid = bitbucketProfile.uuid;
          }
          if (bitbucketProfile.username) {
            token.bitbucketLogin = bitbucketProfile.username;
          }
          if (bitbucketProfile.display_name) {
            token.bitbucketDisplayName = bitbucketProfile.display_name;
          }
        }
      }
      return token;
    },
    async session({ session, token }) {
      // Add provider info to session
      session.accessToken = token.accessToken;
      session.accessTokenExpiresAt = token.accessTokenExpiresAt;
      session.provider = token.provider;

      if (session.user) {
        if (token.provider === "github") {
          session.user.id = token.githubUserId;
          session.user.login = token.githubLogin;
        } else if (token.provider === "bitbucket") {
          session.user.id = token.bitbucketUuid;
          session.user.login = token.bitbucketLogin;
          // Use display name as name if available
          if (token.bitbucketDisplayName) {
            session.user.name = token.bitbucketDisplayName;
          }
        }
      }
      return session;
    },
  },
  pages: {
    error: "/access-denied",
  },
};
