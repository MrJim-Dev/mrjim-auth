import { createRequestAuthClient, sitePath } from "../../../../../lib/server-auth";
import { invalidRequest, publicAuthError, readJsonObject, requiredText } from "../../../../../lib/route-contracts";

export async function POST(request: Request) {
  const body = await readJsonObject(request);
  const email = body === null ? null : requiredText(body.email, 320);
  if (email === null) return invalidRequest();

  const client = await createRequestAuthClient();
  const result = await client.auth.resetPasswordForEmail(email, {
    redirectTo: sitePath("/auth/reset"),
  });
  if (result.error !== null) return publicAuthError(result.error);
  return Response.json({ data: { sent: true } }, {
    headers: { "cache-control": "no-store" },
  });
}
