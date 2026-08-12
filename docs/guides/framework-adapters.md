# Framework adapters

`mrjim-auth` keeps Express and Next.js optional. The package exports structural
adapters, so installing either framework is a project decision rather than an
SDK requirement.

## Express

Mount the framework-neutral auth server with `mrjim-auth/express`:

```ts
import express from "express";
import { toExpressHandler } from "mrjim-auth/express";
import { authServer } from "./auth-server.js";

const app = express();
app.use("/auth/v1", toExpressHandler(authServer));
```

The adapter accepts parsed bodies and raw Node request streams, preserves the
exact path/query, streams the response, and writes multiple `Set-Cookie`
headers separately. It uses the direct socket protocol and IP by default.

Forwarded host, protocol, and IP values are ignored for authority decisions
unless a fixed trusted-proxy hop count is configured:

```ts
app.use(
  "/auth/v1",
  toExpressHandler(authServer, { trustProxy: { hops: 1 } }),
);
```

Only configure proxy trust when every request reaches the app through that
known proxy topology. Malformed or ambiguous forwarded values are rejected.

## Next.js browser client

Use `mrjim-auth/nextjs` in Client Components:

```ts
"use client";

import { createBrowserClient } from "mrjim-auth/nextjs";

export const auth = createBrowserClient(
  process.env.NEXT_PUBLIC_AUTH_URL!,
  process.env.NEXT_PUBLIC_AUTH_KEY!,
  { auth: { storageKey: "web" } },
);
```

The helper returns one immutable client per module realm and storage key.
Reusing a storage key with a different URL, key, fetch/storage adapter, or auth
configuration throws instead of silently sharing the wrong session. This
entrypoint contains browser client code only; it does not expose server,
database, migration, private-key, or administration APIs.

## Next.js server client

Create a fresh client for every request with `mrjim-auth/nextjs/server`:

```ts
import { cookies, headers } from "next/headers";
import { createServerClient } from "mrjim-auth/nextjs/server";

export async function requestAuth() {
  const cookieStore = await cookies();
  const requestHeaders = await headers();

  return createServerClient(
    process.env.AUTH_URL!,
    process.env.AUTH_PUBLISHABLE_KEY!,
    {
      cookies: {
        getAll: () => cookieStore.getAll(),
        setAll: (values) => {
          for (const { name, value, options } of values) {
            cookieStore.set(name, value, options);
          }
        },
      },
      headers: {
        "x-request-id": requestHeaders.get("x-request-id") ?? crypto.randomUUID(),
      },
      auth: { storageKey: "web" },
    },
  );
}
```

Session cookies are deterministic, bounded, and chunked when needed. Writes
default to `HttpOnly`, `SameSite=Lax`, path `/`, and `Secure` when the auth URL
uses HTTPS. HTTPS cannot opt out of `Secure`. For a public HTTPS application
that reaches an internal HTTP auth URL, set `secure: true` explicitly. Local
HTTP development may use the default non-Secure cookie. Rotation replaces the
session and expires stale chunks; sign-out expires all auth chunks.

`auth.getSession()` reads base64url-encoded cookie state and is not
authorization proof. Encoding and `HttpOnly` protect transport/access behavior;
they do not make client-held claims authoritative. Before a Server Component,
Route Handler, or Server Action trusts a user or role, call `auth.getUser()` so
the backend returns a validated identity, or validate the JWT through the
project's backend token boundary. Never authorize from cookie profile or
session fields alone.

A read-only adapter may omit `setAll`, which is suitable for operations that do
not change the session. Any operation that must rotate, create, or clear a
session fails closed with `internal_error` if cookies cannot be written. Perform
mutating auth operations in a Route Handler, Server Action, or middleware
context where the framework permits cookie writes.

Pass only a publishable project key to browser or user-session clients. Private
service keys and administration APIs belong exclusively in the later Node-only
administration boundary and must never be stored in cookies.

## Dependency and hosting posture

These adapters require no paid application, hosted auth vendor, remote OAuth
fixture, or mandatory Express/Next.js runtime dependency. The project owns its
backend and PostgreSQL database; framework packages are installed only by the
application that uses them.
