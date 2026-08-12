# Next.js App Router and SSR

`mrjim-auth` has two Next.js entry points:

- `mrjim-auth/nextjs` is the browser-safe singleton helper for Client Components.
- `mrjim-auth/nextjs/server` creates a fresh request-local client backed by the
  current request's cookies.

The important SSR rule is simple: a cookie is transport state, not proof of
identity. A Server Component, Route Handler, Server Action, or middleware must
call `auth.getUser()` (or validate the JWT at the project's backend boundary)
before it trusts a user, role, or permission. Never authorize from
`auth.getSession()` or from decoded cookie fields.

## Install and environment

The framework adapter is optional. Install Next.js, React, and the local
workspace package in the application that uses it:

```sh
pnpm add next react react-dom mrjim-auth
```

For a self-hosted project, expose only the publishable key to the browser:

```dotenv
MRJIM_AUTH_URL=http://localhost:3001/auth/v1
MRJIM_AUTH_PUBLISHABLE_KEY=publishable-local-key
MRJIM_SITE_URL=http://localhost:3000

# These two are safe to embed in a Client Component when a client-only flow is
# intentionally desired. They are not used as the SSR authorization boundary.
NEXT_PUBLIC_MRJIM_AUTH_URL=http://localhost:3001/auth/v1
NEXT_PUBLIC_MRJIM_AUTH_PUBLISHABLE_KEY=publishable-local-key
```

`MRJIM_AUTH_URL` must be the project's own auth endpoint. The auth server and
PostgreSQL database can run locally, in a container, or on infrastructure the
project controls. No paid auth host is required.

## Browser client

Use the browser entry point only from a Client Component. It uses browser
storage and is suitable for a client-only application or a deliberate
client-side auth surface. It must never be imported into a Server Component,
Route Handler, or server-only module.

```ts
import { createBrowserClient } from "mrjim-auth/nextjs";

const client = createBrowserClient(
  "http://localhost:3001/auth/v1",
  "publishable-local-key",
  { auth: { storageKey: "web", flowType: "pkce" } },
);

const result = await client.auth.signInWithOAuth({
  provider: "google",
  options: {
    redirectTo: "http://localhost:3000/auth/callback",
    skipBrowserRedirect: true,
  },
});

if (result.error === null) window.location.assign(result.data.url);
```

The framework-neutral constructor has the same client namespace and is useful
for a compile-checked smoke test:

```ts compile
import { createClient } from "mrjim-auth";

const client = createClient("http://localhost:3001/auth/v1", "publishable-local-key");
const result = await client.auth.getPermissions();
if (result.error === null) console.log(result.data.permissions);
```

For an SSR application, do not use a browser-local session as the source for a
protected Server Component. The included
`examples/nextjs-app-router` uses browser UI plus same-origin Route Handlers,
so its session is written by the server adapter instead.

## Request-local server client

Call `createServerClient` for every request. Do not cache it in module scope:

```tsx
import { cookies, headers } from "next/headers";
import { createServerClient } from "mrjim-auth/nextjs/server";

export async function createRequestAuth() {
  const cookieStore = await cookies();
  const requestHeaders = await headers();

  return createServerClient(
    process.env.MRJIM_AUTH_URL!,
    process.env.MRJIM_AUTH_PUBLISHABLE_KEY!,
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

The adapter chunks large session records, uses `HttpOnly`, `SameSite=Lax`, and
bounded cookie attributes, and expires stale chunks when a session is rotated
or cleared. A mutable `setAll` adapter is required for login, refresh, OAuth
exchange, password reset, and logout. A read-only adapter is appropriate only
for a read that cannot rotate or clear the session.

The `cookies()` API is writable in Route Handlers and Server Actions. A Server
Component may read the session, but should perform cookie-mutating operations
through a Route Handler or Server Action.

## Authorize a Server Component

The authorization boundary must be the backend-validated user response:

```tsx
import { redirect } from "next/navigation";
import { createRequestAuth } from "./request-auth";

export default async function ProfilePage() {
  const client = await createRequestAuth();
  const { data, error } = await client.auth.getUser();
  if (error !== null || data === null) redirect("/login");

  const permissions = await client.auth.getPermissions();
  return <p>{data.user.email}: {permissions.data?.permissions.join(", ") ?? "no permissions"}</p>;
}
```

`getUser()` sends the bearer session to `/user`, where the project's auth
backend verifies the JWT/session and returns the current identity. If a page
needs a permission, check the returned permission set before rendering the
link and enforce that same permission again in the protected API or backend
operation. Hiding a link is only navigation ergonomics.

The runnable example uses this flow in `src/lib/server-auth.ts` and
`src/app/profile/page.tsx`. Its navigation calls `getUser()` and
`getPermissions()` request-locally, and its profile page is explicitly dynamic.

## Password signup, login, and logout

For an SSR app, post a browser form to same-origin Route Handlers:

1. `POST /api/auth/password` calls `signUp` or `signInWithPassword` with the
   request-local server client.
2. The server adapter persists the resulting session in HttpOnly cookies.
3. The response returns only safe user/status data; it does not serialize access
   or refresh tokens into the page.
4. `POST /auth/logout` calls `signOut({ scope: "local" })`, clears every auth
   cookie chunk, and redirects to `/login`.

The example's `/login` page implements both signup and login. A signup that
requires email confirmation reports a generic next step instead of assuming a
session exists.

## Google OAuth with server-owned PKCE

The safest App Router shape is:

1. A Client Component posts to `POST /api/auth/google`.
2. The Route Handler calls `signInWithOAuth({ provider: "google", ... })` with
   `skipBrowserRedirect: true` and returns only the provider URL.
3. The server adapter stores the PKCE verifier in an HttpOnly cookie.
4. The browser navigates to the returned URL.
5. Google and the auth server return to `/auth/callback`.
6. `GET /auth/callback` calls `exchangeCodeForSession(code)` with the same
   request-local server client, writes the session cookies, and redirects to
   `/profile`.

Configure both allowlists before testing:

- the Google OAuth console must allow the callback URL owned by the project's
  auth server, for example `http://localhost:3001/auth/v1/callback/google`;
- the auth server's `redirects.allowed` must include the app URL
  `http://localhost:3000/auth/callback`;
- the provider configuration must use the project's Google client ID and
  secret, kept on the auth server only.

Do not put the Google client secret, auth server secret key, or admin key in a
`NEXT_PUBLIC_*` variable. The example keeps the PKCE exchange on the server so
the callback does not depend on browser local storage.

## Password recovery

The recovery flow is also split into two Route Handlers:

- `POST /api/auth/recovery/request` calls
  `resetPasswordForEmail(email, { redirectTo: "/auth/reset" })` and always
  shows a generic “if the account exists” message.
- `POST /api/auth/recovery/reset` calls
  `resetPassword({ email, token, password, options: { redirectTo: "/auth/reset" } })`.

The one-time token is purpose-bound and consumed by the auth backend. The
example reset page accepts the email and token from the recovery link, but the
Route Handler still validates both fields and never treats a cookie as reset
proof.

## Middleware and caching

Do not place a request-local client in a module-level singleton. Do not cache a
user-specific Server Component or permission result in a public cache. Calling
`cookies()`, `headers()`, and `auth.getUser()` makes the request dynamic; the
example also declares the profile page with `dynamic = "force-dynamic"` to make
the intent visible.

If middleware needs a coarse redirect, it may check for the presence of the
auth cookie as a routing hint, but the destination page and API must call
`getUser()` or validate the JWT again. Cookie presence alone is not
authorization.

## Local run

Start the project's auth API and PostgreSQL database first, apply the bundled
migrations, configure the environment above, then run:

```sh
pnpm --filter nextjs-app-router dev
```

Open `http://localhost:3000/login`. The full reference app is under
`examples/nextjs-app-router`; it is intentionally free/self-hostable and does
not require Supabase, a paid auth provider, or a hosted database.
