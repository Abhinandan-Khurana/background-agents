import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { controlPlaneFetch } from "@/lib/control-plane";

export async function GET(request: NextRequest) {
  const session = await getServerSession();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const searchParams = request.nextUrl.searchParams;
  const queryString = searchParams.toString();
  const path = queryString ? `/sessions?${queryString}` : "/sessions";

  try {
    const response = await controlPlaneFetch(path);
    const data = await response.json();
    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    console.error("Failed to fetch sessions:", error);
    return NextResponse.json({ error: "Failed to fetch sessions" }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const body = await request.json();

    const accessToken = (session as { accessToken?: string }).accessToken;
    const provider = (session as { provider?: string }).provider;

    // Prepare session body with provider-specific token
    const sessionBody: Record<string, any> = {
      ...body,
      vcsProvider: provider,
    };

    if (provider === "bitbucket") {
      sessionBody.bitbucketToken = accessToken;
      sessionBody.bitbucketUuid = session.user.id;
      sessionBody.bitbucketLogin = session.user.login;
      sessionBody.bitbucketDisplayName = session.user.name;
      sessionBody.bitbucketEmail = session.user.email;
    } else {
      // Default to GitHub
      sessionBody.githubToken = accessToken;
      sessionBody.githubLogin = session.user.login;
      sessionBody.githubName = session.user.name;
      sessionBody.githubEmail = session.user.email;
    }

    const response = await controlPlaneFetch("/sessions", {
      method: "POST",
      body: JSON.stringify(sessionBody),
    });

    const data = await response.json();
    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    console.error("Failed to create session:", error);
    return NextResponse.json({ error: "Failed to create session" }, { status: 500 });
  }
}
