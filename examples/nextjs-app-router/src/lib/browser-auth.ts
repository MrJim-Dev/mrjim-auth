"use client";

import { createBrowserClient } from "mrjim-auth/nextjs";
import type { MrJimAuthClient } from "mrjim-auth";

let client: MrJimAuthClient | undefined;

function requiredPublicEnv(name: string, value: string | undefined): string {
  if (value === undefined || value.trim() === "") {
    throw new Error(`${name} is required for the browser auth client`);
  }
  return value;
}

/**
 * Browser-only client for client-rendered applications that intentionally
 * keep their session in browser storage. The SSR example uses the server
 * client for session writes so protected Server Components receive HttpOnly
 * cookies; do not use this client as a server authorization boundary.
 */
export function getBrowserAuthClient(): MrJimAuthClient {
  if (client !== undefined) return client;
  const created = createBrowserClient(
    requiredPublicEnv("NEXT_PUBLIC_MRJIM_AUTH_URL", process.env.NEXT_PUBLIC_MRJIM_AUTH_URL),
    requiredPublicEnv("NEXT_PUBLIC_MRJIM_AUTH_PUBLISHABLE_KEY", process.env.NEXT_PUBLIC_MRJIM_AUTH_PUBLISHABLE_KEY),
    {
      auth: {
        storageKey: "nextjs-client",
        autoRefreshToken: true,
        persistSession: true,
        detectSessionInUrl: true,
        flowType: "pkce",
      },
    },
  );
  client = created;
  return created;
}
