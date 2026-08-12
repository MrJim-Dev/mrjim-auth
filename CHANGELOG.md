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
