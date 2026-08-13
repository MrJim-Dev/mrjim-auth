# mrjim-auth

Project-owned authentication and object storage for Node.js and PostgreSQL,
with a familiar Supabase-shaped client API. Each application runs its own auth server and keeps
users, sessions, identities, roles, permissions, API keys, and audit events in
its own PostgreSQL database.

The package includes:

- browser-safe `createClient(...).auth` and `createClient(...).storage` APIs;
- a server-only S3 adapter with logical bucket and prefix mappings;
- a Node-only `createAdminClient(...).auth.admin` API;
- a framework-neutral Fetch `AuthServer` plus Express and Next.js adapters;
- forward-only migrations for a clean `auth` schema;
- email/password, OTP, recovery, Google OAuth and generic OIDC;
- dynamic scoped roles and permissions;
- project-owned mail and rate-limit adapters.

It has no Supabase runtime dependency and no mandatory paid or hosted service.
PostgreSQL, S3-compatible infrastructure, signing keys, email delivery, deployment, and observability remain
under the installing project's control.

## Start here

1. Read the [five-minute setup](docs/getting-started.md).
2. Review the [architecture](docs/concepts/architecture.md) and
   [security checklist](docs/security.md).
3. Choose the [Express](docs/guides/express.md) or
   [Next.js App Router](docs/guides/ssr-nextjs.md) guide.
4. Check the [Supabase compatibility matrix](docs/compatibility/supabase-auth.md)
   before migrating an existing application.

## Runtime support

- Node.js 24 or newer
- PostgreSQL 15, 16, or 17
- modern browsers with Fetch, Web Crypto, `TextEncoder`, and `URL`

The v1 package is ESM-only. The browser entry never imports Node-only server or
database code.

## Status

Version `0.1.0` is the first v1 release candidate. See [CHANGELOG.md](CHANGELOG.md)
and [implementation status](docs/implementation-status.md) for verified scope.

## License and cost posture

All mandatory runtime libraries are free/open-source. A project may connect its
own SMTP server or another mail transport; paid email, OAuth, cache, monitoring,
or identity vendors are optional integrations, never requirements.
