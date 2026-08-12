import { NextResponse, type NextRequest } from "next/server";
import { createRequestAuthClient } from "../../../lib/server-auth";

function loginFailure(request: NextRequest) {
  const url = new URL("/login", request.url);
  url.searchParams.set("error", "oauth_callback_failed");
  return NextResponse.redirect(url);
}

/** Exchanges the provider callback code using the PKCE verifier in the server cookie. */
export async function GET(request: NextRequest) {
  const code = request.nextUrl.searchParams.get("code");
  if (code === null || code.trim() === "") return loginFailure(request);

  const client = await createRequestAuthClient();
  const result = await client.auth.exchangeCodeForSession(code);
  if (result.error !== null) return loginFailure(request);
  return NextResponse.redirect(new URL("/profile", request.url));
}
