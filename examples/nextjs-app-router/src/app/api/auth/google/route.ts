import { createRequestAuthClient, sitePath } from "../../../../lib/server-auth";
import { invalidRequest, publicAuthError } from "../../../../lib/route-contracts";

/** Starts Google OAuth with a server-owned PKCE cookie. */
export async function POST() {
  const client = await createRequestAuthClient();
  const result = await client.auth.signInWithOAuth({
    provider: "google",
    options: {
      redirectTo: sitePath("/auth/callback"),
      skipBrowserRedirect: true,
    },
  });
  if (result.error !== null) return publicAuthError(result.error);
  if (result.data.url.length === 0) return invalidRequest();
  return Response.json({ data: { url: result.data.url } }, {
    headers: { "cache-control": "no-store" },
  });
}
