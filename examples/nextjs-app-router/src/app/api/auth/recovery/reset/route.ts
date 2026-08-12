import { createRequestAuthClient, sitePath } from "../../../../../lib/server-auth";
import { invalidRequest, publicAuthError, readJsonObject, recoveryFrom } from "../../../../../lib/route-contracts";

export async function POST(request: Request) {
  const body = await readJsonObject(request);
  const recovery = body === null ? null : recoveryFrom(body);
  if (recovery === null) return invalidRequest();

  const client = await createRequestAuthClient();
  const result = await client.auth.resetPassword({
    email: recovery.email,
    token: recovery.token,
    password: recovery.password,
    options: { redirectTo: sitePath("/auth/reset") },
  });
  if (result.error !== null) return publicAuthError(result.error);
  return Response.json({ data: { user: result.data.user } }, {
    headers: { "cache-control": "no-store" },
  });
}
