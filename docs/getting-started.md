# Five-minute setup

mrjim-auth is an SDK and server library, not a hosted identity service. Your
project supplies PostgreSQL, an HTTP process, ES256 signing keys, opaque secret
material, and a mail adapter.

## 1. Install

```sh
pnpm add mrjim-auth
```

Use Node.js 24+ and PostgreSQL 15-17. Keep `mrjim-auth` at one exact version in
production so packaged migrations and runtime code move together.

## 2. Configure server-only environment variables

```dotenv
DATABASE_URL=postgres://app:password@127.0.0.1:5432/app
AUTH_BASE_URL=http://localhost:3000/auth/v1
AUTH_SITE_URL=http://localhost:5173
AUTH_TOKEN_HASH_KEY=<at-least-32-random-bytes-as-unpadded-base64url>
AUTH_ENCRYPTION_KEY=<at-least-32-random-bytes-as-unpadded-base64url>
AUTH_ES256_PRIVATE_JWK=<server-only-private-JWK-JSON>
AUTH_ES256_KEY_ID=primary-2026-08
AUTH_PUBLISHABLE_KEY=<optional-project-public-key>
AUTH_SECRET_KEY=<server-only-admin-key>
```

Never prefix private keys, database URLs, token-hash keys, encryption keys, or
admin keys with a browser-public environment prefix.

## 3. Apply and verify migrations

Migrations are explicit and forward-only. The server never mutates schema at
startup.

```sh
DATABASE_URL="$DATABASE_URL" pnpm exec mrjim-auth migrate status
DATABASE_URL="$DATABASE_URL" pnpm exec mrjim-auth migrate up
DATABASE_URL="$DATABASE_URL" pnpm exec mrjim-auth migrate verify
```

You can also call `migrate(pool, { direction: "up" })` from
`mrjim-auth/postgres`. Migration checksums are recorded in
`auth.schema_migrations`; checksum drift fails closed.

## 4. Compose and mount the auth server

Create a PostgreSQL adapter, supply your mailer's `send()` method, configure
exact redirects, and mount the framework-neutral server at `/auth/v1`. Complete
mounts are in the [Express guide](guides/express.md) and [Next.js guide](guides/ssr-nextjs.md).

Production `baseUrl`, `siteUrl`, redirects, and OIDC issuers must use HTTPS.
`baseUrl` must exactly match the signing issuer. Generate the checked-in OpenAPI
document from the same server contract with `generateOpenApiDocument()`.

## 5. Create the application client

```ts compile
import { createClient } from "mrjim-auth";

export const auth = createClient(
  "http://localhost:3000/auth/v1",
  "project-publishable-key",
  {
    auth: {
      flowType: "pkce",
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: true,
      storageKey: "my-project",
    },
  },
);
```

Expected auth failures resolve as `{ data, error }`; invalid programming or
configuration input throws. Check `error` before reading `data`.

## 6. Seed authorization

Create `user` and `admin` roles, create project permissions such as
`invoice.read`, attach permissions to roles, then assign roles. The admin client
or repository transaction may perform seeding. Role and permission policy is
described in [roles and permissions](guides/roles-permissions.md).

## 7. Production checklist

- terminate TLS before auth traffic and configure proxy trust explicitly;
- rotate signing keys while retaining verification keys for unexpired tokens;
- use a shared PostgreSQL rate limiter for multi-instance deployments;
- make mail delivery non-logging and secret-safe;
- use exact redirect allowlists;
- authorize on the server with validated user/JWT state;
- back up the project database and test forward migrations on a restore;
- monitor stable error codes, request IDs, and redacted audit events.
