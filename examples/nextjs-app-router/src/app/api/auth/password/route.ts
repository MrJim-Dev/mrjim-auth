import { createRequestAuthClient } from "../../../../lib/server-auth";
import { credentialsFrom, invalidRequest, publicAuthError, readJsonObject, requiredText } from "../../../../lib/route-contracts";

export async function POST(request: Request) {
  const body = await readJsonObject(request);
  if (body === null) return invalidRequest();

  const mode = requiredText(body.mode, 16);
  const credentials = credentialsFrom(body);
  if (mode !== "login" && mode !== "signup") return invalidRequest();
  if (credentials === null) return invalidRequest();

  const client = await createRequestAuthClient();
  const result = mode === "login"
    ? await client.auth.signInWithPassword(credentials)
    : await client.auth.signUp({ email: credentials.email, password: credentials.password });

  if (result.error !== null) return publicAuthError(result.error);
  return Response.json({
    data: {
      user: result.data.user,
      authenticated: result.data.session !== null,
    },
  }, {
    headers: { "cache-control": "no-store" },
  });
}
