# Supabase Auth compatibility

`mrjim-auth` intentionally uses familiar Supabase Auth names and result
nesting while keeping the database and backend project-owned. This matrix is
for the v1 surface; a status of `Compatible` means the public shape is close
enough for the same calling pattern, not that the services are wire- or
schema-identical.

The only status labels in this matrix are `Compatible`, `Different`, and
`Unsupported in v1`.

## Construction and options

| Supabase-shaped surface | Status | v1 behavior |
| --- | --- | --- |
| `createClient(url, key, options?)` | Compatible | Import `createClient` from `mrjim-auth`; the URL is the project's `/auth/v1` endpoint and the publishable key is sent as `apikey`. |
| `auth.autoRefreshToken` | Compatible | Expiry-aware client refresh scheduling. Browser default is `true`; non-browser default is `false`. |
| `auth.persistSession` | Compatible | Uses the configured storage adapter; browser default is `true`. |
| `auth.detectSessionInUrl` | Compatible | Consumes browser OAuth callback data; browser default is `true`. |
| `auth.flowType` | Different | Only `"pkce"` is accepted. Other Supabase flow values are not accepted. |
| `auth.storage` | Compatible | Supports synchronous or asynchronous `getItem`, `setItem`, and `removeItem`. |
| `auth.storageKey` | Compatible | Namespaces session, PKCE, locks, and local events. |
| `auth.lock` | Compatible | Supports a project-provided cross-context lock callback. |
| `auth.debug` | Different | Boolean or redacted callback; secrets and tokens must never be logged. |
| `auth.skipAutoInitialize` | Different | v1-specific option to defer initial storage/URL processing. |
| `global.fetch` and `global.headers` | Compatible | Inject a fetch implementation and validated global request headers. |
| Response nesting `{ data, error }` | Compatible | Expected operations return `{ data: T, error: null }` or `{ data: null, error: AuthError }`. |
| Error class/details | Different | Codes/messages/status are stable but are project SDK contracts, not Supabase error identity. |

## Client auth namespace

| Method or event | Status | v1 behavior |
| --- | --- | --- |
| `auth.signUp` | Compatible | Email/password signup with optional redirect and JSON user metadata; session may be `null` pending confirmation. |
| `auth.signInWithPassword` | Compatible | Email/password sign-in returning `{ user, session }`. |
| `auth.signInWithOtp` | Compatible | Magic link or email OTP issuance; the `type` aliases are accepted. |
| `auth.verifyOtp` | Compatible | Verifies a purpose-bound signup confirmation, email OTP, or magic-link token. Use `type: "signup"` for the confirmation token issued by `signUp`. |
| `auth.signInWithOAuth` | Compatible | Starts provider authorization using authorization-code PKCE. |
| `auth.exchangeCodeForSession` | Compatible | Exchanges a callback code using the locally stored PKCE verifier. |
| `auth.resetPasswordForEmail` | Compatible | Non-enumerating recovery-message request. |
| `auth.resetPassword` | Different | Explicit v1 method consumes `{ email, token, password, options? }`. |
| `auth.resend` | Compatible | Resends `signup` or `recovery` messages. |
| `auth.getSession` | Compatible | Reads a local session, but v1 documents it as advisory and non-authoritative. |
| `auth.getUser` | Compatible | Fetches the authoritative current user; optional JWT can override the stored token. |
| `auth.setSession` | Compatible | Validates/refreshes and persists a supplied session. |
| `auth.refreshSession` | Compatible | Rotates a refresh token under a cross-context lock. |
| `auth.updateUser` | Different | v1 currently supports email and user metadata; password/phone update routes are absent. |
| `auth.getUserIdentities` | Compatible | Returns provider-safe linked identities without provider secrets. |
| `auth.linkIdentity` | Compatible | Starts an authenticated OAuth/OIDC PKCE link flow. |
| `auth.unlinkIdentity` | Compatible | Removes an identity subject to server login-method policy. |
| `auth.getPermissions` | Different | Project RBAC hint only; backend authorization remains authoritative. |
| `auth.signOut` | Compatible | Supports `local`, `global`, and `others` session scopes. |
| `auth.onAuthStateChange` | Compatible | Emits the six v1 lifecycle events below and returns `{ unsubscribe() }`. |
| `auth.startAutoRefresh` | Compatible | Starts expiry-aware refresh scheduling. |
| `auth.stopAutoRefresh` | Compatible | Stops scheduling without signing out. |
| `auth.dispose` | Different | Explicit v1 lifecycle cleanup for timers, channels, listeners, and subscriptions. |

The six event names are `INITIAL_SESSION`, `SIGNED_IN`, `SIGNED_OUT`,
`TOKEN_REFRESHED`, `USER_UPDATED`, and `PASSWORD_RECOVERY`. Events are local
client lifecycle notifications; they are not a replacement for server audit
records or authorization checks.

## Server-side and SSR surface

| Surface | Status | v1 behavior |
| --- | --- | --- |
| SSR request-local client | Compatible | `createServerClient` from `mrjim-auth/nextjs/server` uses a project cookie adapter and disables browser URL detection/auto-refresh. |
| Browser singleton helper | Compatible | `createBrowserClient` from `mrjim-auth/nextjs` reuses one client per storage key and rejects conflicting configuration. |
| Cookie/session trust | Different | `getSession()` is advisory; SSR authorization must call `getUser()` or verify a token in the backend. |
| Express integration | Different | Use the framework-neutral `AuthServer` with `toExpressHandler`; Express is not a package dependency. |
| Server/admin client | Different | `createAdminClient` is a Node-only project endpoint client and sends a secret only as `apikey`. |

## Admin namespace

The following 20 admin methods are available under
`createAdminClient(...).auth.admin`. Their names are intentionally familiar,
but response payloads and policy are project-owned.

| Method | Status | v1 behavior |
| --- | --- | --- |
| `listUsers` | Compatible | Paged users, default page 1/per-page 50, max 100. |
| `getUserById` | Compatible | Returns `{ user }` for a UUID. |
| `findUser` | Different | Takes `{ email }` and returns `{ user: User \| null }`. |
| `createUser` | Compatible | Sends a project-owned admin user object. |
| `updateUserById` | Compatible | Sends a project-owned admin update patch. |
| `deleteUser` | Different | Only soft deletion is supported; hard deletion is rejected. |
| `inviteUserByEmail` | Compatible | Sends `{ email, options? }` with options nested. |
| `listRoles` | Different | Dynamic project RBAC roles are first-class auth records. |
| `createRole` | Different | Supports key, name, description, rank, and system protection. |
| `updateRole` | Different | System/rank policy is enforced transactionally. |
| `deleteRole` | Different | Protected/system roles cannot be deleted. |
| `setRolePermissions` | Different | Replaces dynamic permission IDs atomically. |
| `setRoleInheritance` | Different | Replaces inherited roles and rejects cycles. |
| `assignRole` | Different | Supports global or `{ type, id }` scoped assignments. |
| `unassignRole` | Different | Removes a matching global or scoped assignment. |
| `listPermissions` | Different | Lists dynamic `resource.action` permissions. |
| `createPermission` | Different | Supports exact, `resource.*`, and `*.*` permission keys. |
| `updatePermission` | Different | Updates a project permission record. |
| `deletePermission` | Different | Uses policy/role locking and denies unsafe deletion. |
| `listAudit` | Different | Reads immutable, redacted, paginated project audit events. |

`createAdminClient` itself is `Different`: it is Node-only, not browser-safe,
and has no bearer header. Keep the secret out of all user-controlled code.

## Explicitly absent in v1

| Supabase client capability | Status | v1 statement |
| --- | --- | --- |
| `from` query builder | Unsupported in v1 | `mrjim-auth` is an auth SDK; it does not expose a general database query builder. |
| `rpc` | Unsupported in v1 | Database procedures remain the project's own backend concern. |
| `storage.from(bucket).createSignedUrl` | Compatible | Requests an authorized, time-bounded private object URL from the project storage API. |
| `storage.from(bucket).createSignedUploadUrl` | Different | Requires content type, content length, and a base64 SHA-256 checksum; returns every header that must be sent to S3. |
| `storage.from(bucket).remove` | Compatible | Deletes one bounded list of validated object keys after project authorization. |
| General bucket administration | Unsupported in v1 | Bucket creation, policy editing, and arbitrary provider administration remain server-owned infrastructure concerns. |
| `realtime` | Unsupported in v1 | No hosted or self-hosted realtime client is bundled. |
| Phone auth | Unsupported in v1 | Phone fields are represented in the schema, but phone sign-in/OTP routes are not implemented. |
| MFA | Unsupported in v1 | `aal` is stored for session compatibility, but MFA enrollment/challenge APIs are absent. |
| Anonymous auth | Unsupported in v1 | Every v1 session is tied to an authenticated project user. |
| SAML | Unsupported in v1 | v1 supports Google and generic OIDC authorization-code PKCE providers only. |

The package also does not claim Supabase's managed dashboard, hosted email,
managed database, hosted storage, realtime, or billing features. It can be deployed
with free/self-hosted project infrastructure and has no paid or hosted
dependency requirement.

## Migration expectation

The SDK surface is intentionally similar, but the database is not a drop-in
Supabase Auth schema. Migrate users, identities, role data, active sessions,
redirect configuration, and OAuth provider settings as an explicit project
operation. See [Migrating to Supabase](../guides/migrating-to-supabase.md) for
the reverse migration checklist.
