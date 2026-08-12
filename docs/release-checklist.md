# v0.1.0 release checklist

This checklist is completed only from a clean checkout of the exact release
candidate. `pnpm release:check` is the single required gate and must finish with
zero skipped security or migration-version suites.

## Platform

- [x] Node.js 24 or newer recorded.
- [x] pnpm 10.30.3 frozen install passes.
- [x] PostgreSQL 15.18 fresh and every-boundary upgrade passes.
- [x] PostgreSQL 16.14 fresh and every-boundary upgrade passes.
- [x] PostgreSQL 17.10 fresh and every-boundary upgrade passes.

## Product and security

- [x] Build, typecheck, lint, all 433 Vitest tests, and 11 real Chrome tests pass.
- [x] Abuse-path suite covers limits, enumeration, replay, redirects, linking,
      CSRF-sensitive requests, expired roles, browser secret keys, audit data,
      and oversized metadata.
- [x] Supabase-shaped surface contract passes.
- [x] Browser bundles contain no Node, PostgreSQL, Argon2, migrations, private
      signing code, or Node-only administration implementation.
- [x] Express and Next.js examples typecheck and test (4/4 each).
- [x] Next.js 16.3.0 optimized production build passes.

## Schema and documentation

- [x] All six forward migrations retain approved checksums.
- [x] Fresh install and upgrades preserve sentinel users/roles/permissions.
- [x] README, API/schema references, OpenAPI, security guide, migration guide,
      compatibility matrix, and changelog are current.
- [x] `docs:check` and compile-tagged documentation examples pass.

## Package

- [x] `pnpm pack --dry-run` includes JavaScript,
      declarations, source maps, SQL migrations, README, license, and manifest.
- [x] Package excludes tests, environment files, local databases, artifacts,
      credentials, and workspace-only files.
- [x] A real tarball is created under ignored `artifacts/` and its 289-file list is
      manually compared with the dry-run inspection.
- [x] Version, changelog date, Node/PostgreSQL support, and known Supabase
      differences are correct.

## Publication boundary

- [x] Licensing is intentionally `UNLICENSED` for authorized projects. Replace
      it with the chosen public license before publishing to a public registry.
- [x] Registry/account publication is separately authorized; release checks do
      not publish, deploy, email, or mutate a remote database.
