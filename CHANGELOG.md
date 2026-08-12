# Changelog

All notable changes are recorded here. The project follows Semantic Versioning
once `1.0.0` is released.

## 0.1.0 - 2026-08-12

Initial v1 release candidate:

- project-owned PostgreSQL `auth` schema and forward-only migration runner;
- browser-safe Supabase-shaped client and Node-only administration client;
- email/password, OTP, magic-link, recovery, Google OAuth and generic OIDC;
- rotating refresh sessions, ES256 access tokens, JWKS, and scoped sign-out;
- dynamic roles, inheritance, scoped permissions, API keys, and audit history;
- framework-neutral server plus Express and Next.js adapters;
- memory and PostgreSQL rate limiting;
- OpenAPI contract, guides, compatibility matrix, and runnable examples.

Known v1 exclusions include phone auth, MFA, anonymous auth, SAML, and non-auth
Supabase products such as database query builders, RPC, Storage, and Realtime.

Release verification covers Node.js 24+, PostgreSQL 15.18/16.14/17.10, the
23-method browser auth namespace, 20-method Node admin namespace, Express and
Next.js adapters, deterministic OpenAPI, browser bundle isolation, and real
Chrome lifecycle behavior. The clean schema is current through:

- `0001_core`
- `0002_authorization`
- `0003_oauth_operations`
- `0004_repository_hardening`
- `0005_oauth_callback`
- `0006_admin_operations`

The package is currently `UNLICENSED` for authorized projects. Choosing a
public license is required before public registry publication.
