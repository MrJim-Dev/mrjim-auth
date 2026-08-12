# Express

The Express adapter converts each request to the framework-neutral Fetch
boundary and writes the `AuthServer` response back without merging duplicate
cookies or buffering unbounded bodies. Express remains an optional application
dependency; `mrjim-auth` does not require it at runtime.

## Five-minute local run

The complete project is in `examples/express-api` and uses only free,
self-hostable dependencies.

```sh
pnpm install
cp examples/express-api/.env.example examples/express-api/.env
pnpm --filter express-api migrate
pnpm --filter express-api seed
pnpm --filter express-api dev
```

Set `DATABASE_URL`, `AUTH_BASE_URL=http://localhost:3000/auth/v1`,
`AUTH_SITE_URL`, token/encryption/rate-limit keys, an ES256 private JWK and key
ID, token audience, and exact allowed redirects. Generate a publishable key
after migration with:

```sh
MRJIM_AUTH_API_KEY_HASH_KEY="$AUTH_TOKEN_HASH_KEY" \
  pnpm exec mrjim-auth keys generate --kind publishable --name express-local
```

The raw key is returned once. Put it in the browser client only; keep secret
admin keys server-only.

## Mount the server

```ts compile
import { toExpressHandler, type ExpressRequest, type ExpressResponse } from "mrjim-auth/express";
import type { AuthServer } from "mrjim-auth/server";

export function authHandler(server: AuthServer) {
  const handler = toExpressHandler(server);
  return (request: ExpressRequest, response: ExpressResponse) => handler(request, response);
}
```

In Express, mount that handler at `/auth/v1`. The adapter uses `originalUrl`, so
the full configured base path is preserved even though Express trims a mounted
router's `url`.

If and only if a known reverse proxy terminates TLS, pass
`{ trustProxy: { hops: 1 } }` (or the exact hop count). The adapter rejects
ambiguous forwarding headers and derives one canonical client address, host,
and protocol. Do not enable proxy trust merely because production uses a load
balancer—verify the actual chain first.

## PostgreSQL and migrations

The example calls `migrate(pool, { direction: "up" })` in an explicit release
script, followed by `verifySchema(pool)`. Server startup does not migrate. The
seed script transactionally upserts `user` and protected `admin` roles, creates
`invoice.read`, and attaches it idempotently.

## Protect project routes

`GET /invoices` copies only `apikey`, bearer authorization, optional origin,
and request ID into a new Fetch `Request`, then calls:

```ts compile
import type { AuthServer } from "mrjim-auth/server";

export async function requireInvoiceRead(server: AuthServer, request: Request) {
  return server.authorize(request, { all: ["invoice.read"] });
}
```

`AuthServer.authorize()` validates the API key, bearer JWT/session, and current
database-backed permissions before returning the subject. A browser
`getPermissions()` result may hide navigation, but it is never enough to return
invoice data.

## Mail, limits, and production

The example's development mailer logs only template and destination, never
template variables. Replace it with project SMTP before production. It uses the
durable `PostgresRateLimiter`, so multiple Node instances share abuse buckets.

Production requires HTTPS URLs, exact redirects, secure key storage, explicit
proxy trust, database backups, tested key rotation, and redacted monitoring.
No Supabase account, paid auth application, hosted cache, or paid email provider
is required.
