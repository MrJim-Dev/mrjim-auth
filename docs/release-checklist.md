# v0.1.0 release checklist

This checklist is completed only from a clean checkout of the exact release
candidate. `pnpm release:check` is the single required gate and must finish with
zero skipped security or migration-version suites.

## Platform

- [ ] Node.js 24 or newer recorded.
- [ ] pnpm 10.30.3 frozen install passes.
- [ ] PostgreSQL 15 fresh and every-boundary upgrade passes.
- [ ] PostgreSQL 16 fresh and every-boundary upgrade passes.
- [ ] PostgreSQL 17 fresh and every-boundary upgrade passes.

## Product and security

- [ ] Build, typecheck, lint, all Vitest tests, and real Chrome tests pass.
- [ ] Abuse-path suite covers limits, enumeration, replay, redirects, linking,
      CSRF-sensitive requests, expired roles, browser secret keys, audit data,
      and oversized metadata.
- [ ] Supabase-shaped surface contract passes.
- [ ] Browser bundles contain no Node, PostgreSQL, Argon2, migrations, private
      signing code, or Node-only administration implementation.
- [ ] Express and Next.js examples typecheck and test.
- [ ] Next.js optimized production build passes.

## Schema and documentation

- [ ] All six forward migrations retain approved checksums.
- [ ] Fresh install and upgrades preserve sentinel users/roles/permissions.
- [ ] README, API/schema references, OpenAPI, security guide, migration guide,
      compatibility matrix, and changelog are current.
- [ ] `docs:check` and compile-tagged documentation examples pass.

## Package

- [ ] `npm pack --dry-run`/`pnpm pack --dry-run` includes JavaScript,
      declarations, source maps, SQL migrations, README, license, and manifest.
- [ ] Package excludes tests, environment files, local databases, artifacts,
      credentials, and workspace-only files.
- [ ] A real tarball is created under ignored `artifacts/` and its file list is
      manually compared with the dry-run inspection.
- [ ] Version, changelog date, Node/PostgreSQL support, and known Supabase
      differences are correct.

## Publication boundary

- [ ] Licensing is intentionally `UNLICENSED` for authorized projects. Replace
      it with the chosen public license before publishing to a public registry.
- [ ] Registry/account publication is separately authorized; release checks do
      not publish, deploy, email, or mutate a remote database.
