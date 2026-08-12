import { NextResponse } from "next/server";
import { createRequestAuthClient } from "../../../lib/server-auth";

export async function POST(request: Request) {
  const client = await createRequestAuthClient();
  await client.auth.signOut({ scope: "local" });
  return NextResponse.redirect(new URL("/login", request.url));
}
