# Client reference

The root `mrjim-auth` entrypoint is the browser-safe, isomorphic client. It
talks to the project's own auth and storage HTTP endpoints; it does not connect
to a database and it never accepts a server secret.

## `createClient`

```ts compile
import { createClient, type ClientOptions } from "mrjim-auth";

const options: ClientOptions = {
  auth: {
    autoRefreshToken: true,
    persistSession: true,
    detectSessionInUrl: true,
    flowType: "pkce",
    storageKey: "web",
  },
  global: {
    headers: { "x-client-name": "example-web" },
  },
};

const client = createClient(
  "https://example.test/auth/v1",
  "publishable-project-key",
  options,
);

const subscription = client.auth.onAuthStateChange((event, session) => {
  if (event === "SIGNED_IN") console.log(session?.user.id);
});
subscription.unsubscribe();
client.auth.dispose();
```

Signature:

```ts
createClient(
  authUrl: string,
  publishableKey?: string,
  options?: ClientOptions,
): MrJimAuthClient
```

`authUrl` is the absolute URL of the project's auth endpoint, normally ending
in `/auth/v1`. `publishableKey` is sent as the `apikey` header and may be
exposed to a browser. The optional `global.fetch` and `auth.storage` values
are captured at construction. The returned client and its `auth` namespace
and `storage` namespaces are immutable. By default, an auth URL ending in
`/auth/v1` maps storage calls to the sibling `/storage/v1` endpoint. Set
`storage.url` when the storage API is hosted elsewhere.

Malformed configuration or method input throws an
`AuthConfigurationError`/`AuthProgrammingError`. Expected HTTP and auth
failures resolve as an `AuthResult` instead of rejecting.

## Client options

Only the following options are accepted. Unknown fields are not part of the
public contract.

| Option | Meaning | Default |
| --- | --- | --- |
| `auth.autoRefreshToken` | Schedule refresh before access-token expiry. | `true` in a browser, otherwise `false`. |
| `auth.persistSession` | Persist the session through the configured storage. | `true` in a browser, otherwise `false`. |
| `auth.detectSessionInUrl` | Consume an auth callback from the current browser URL. | `true` in a browser, otherwise `false`. |
| `auth.flowType` | OAuth flow. Only `"pkce"` is accepted in v1. | `"pkce"`. |
| `auth.storage` | Synchronous or asynchronous `getItem`, `setItem`, and `removeItem` adapter. | Browser storage when available; otherwise no storage. |
| `auth.storageKey` | Namespace for sessions, PKCE transactions, locks, and events. | `"default"`. |
| `auth.lock` | Optional cross-context lock `(name, acquireTimeout, callback)`. | Internal lock behavior. |
| `auth.debug` | `boolean` or redacted diagnostic callback. | Disabled. |
| `auth.skipAutoInitialize` | Skip initial storage/URL processing. | `false`. |
| `global.fetch` | Fetch implementation for browser, SSR, tests, or a custom runtime. | `globalThis.fetch`. |
| `global.headers` | Additional validated request headers. | `{}`. |
| `storage.url` | Absolute storage API URL. | Sibling `/storage/v1` URL. |

See the [storage reference](storage.md) for object operations and the
server-only S3 adapter.

The client never interprets `auth.getSession()` as authorization proof. It is a
local storage read. Server-rendered code and APIs should use `auth.getUser()`
or independently validate the project's access token before authorizing.

## Result and error shape

All expected operations return the mutually exclusive shape below. The
successful payload is under `data`; failures have `data: null` and a safe
`AuthError` under `error`.

```ts compile
import { createClient, type AuthResult, type User } from "mrjim-auth";

async function example(): Promise<void> {
  const client = createClient("https://example.test/auth/v1", "publishable-key");
  const result: AuthResult<{ readonly user: User }> = await client.auth.getUser();

  if (result.error !== null) {
    console.error(result.error.code, result.error.status, result.error.request_id);
  } else {
    console.log(result.data.user.id);
  }
}

void example();
```

`AuthError` contains `name: "AuthError"`, `message`, an HTTP-compatible
`status`, a stable public `code`, and an optional `request_id`. Credentials,
provider secrets, and enumeration-sensitive internal details are not returned.

## `auth` methods

The `auth` namespace has 23 methods/events. Every async method below resolves a
`Promise<AuthResult<...>>`.

| Method | Signature | Successful `data` |
| --- | --- | --- |
| `signUp` | `signUp(input: SignUpInput)` | `{ user, session }`; either can be `null` when email confirmation is required. |
| `signInWithPassword` | `signInWithPassword(input: PasswordSignInInput)` | `{ user, session }`. |
| `signInWithOtp` | `signInWithOtp(input: OtpSignInInput)` | `{ user, session }`; normally both are `null` until verification. |
| `verifyOtp` | `verifyOtp(input: VerifyOtpInput)` | `{ user, session }`; supports `email_otp`, `magic_link`, and signup confirmation via `type: "signup"`. A session is issued when verification authenticates the user. |
| `signInWithOAuth` | `signInWithOAuth(input: OAuthInput)` | `{ provider, url }`; the URL is the project/provider authorization URL. |
| `exchangeCodeForSession` | `exchangeCodeForSession(code: string)` | `{ user, session }`. Uses the stored PKCE verifier. |
| `resetPasswordForEmail` | `resetPasswordForEmail(email: string, options?: RecoveryOptions)` | `{ sent: true }`; the response is non-enumerating. |
| `resetPassword` | `resetPassword(input: ResetPasswordInput)` | `{ user }`. Consumes a purpose-bound recovery proof. |
| `resend` | `resend(input: ResendInput)` | `{ sent: true }`. `type` is `"signup"` or `"recovery"`. |
| `getSession` | `getSession()` | `{ session: Session \| null }`; local and advisory. |
| `getUser` | `getUser(jwt?: string)` | `{ user }`; server-authoritative. An optional JWT overrides the stored access token. |
| `setSession` | `setSession(session: Session)` | `{ user, session }`; validates/refreshes and persists the supplied session. |
| `refreshSession` | `refreshSession(session?: Session)` | `{ user, session }`; rotates the refresh token under the configured lock. |
| `updateUser` | `updateUser(attributes: UpdateUserAttributes)` | `{ user }`; v1 supports email and user metadata. |
| `getUserIdentities` | `getUserIdentities()` | `{ identities }`; provider secrets are removed. |
| `linkIdentity` | `linkIdentity(input: OAuthInput)` | `{ provider, url }`; starts an authenticated PKCE link flow. |
| `unlinkIdentity` | `unlinkIdentity(identity: Pick<Identity, "id"> \| Identity)` | `null`; server policy may reject removal of the last login method. |
| `getPermissions` | `getPermissions(options?: { scope?: PermissionScope })` | `{ permissions }`; an interface hint, never the server's authorization decision. |
| `signOut` | `signOut(options?: { scope?: SignOutScope })` | `null`; scope is `"local"`, `"global"`, or `"others"`. |
| `onAuthStateChange` | `onAuthStateChange(callback: AuthStateCallback)` | `AuthSubscription`; call `unsubscribe()`. |
| `startAutoRefresh` | `startAutoRefresh()` | `void`; starts expiry-aware scheduling. |
| `stopAutoRefresh` | `stopAutoRefresh()` | `void`; stops scheduling without signing out. |
| `dispose` | `dispose()` | `void`; releases timers, listeners, channels, and subscriptions. |

### Input types

`SignUpInput` is `{ email, password, options? }`; `PasswordSignInInput` is
`{ email, password }`; and `UpdateUserAttributes` supports `email`, `data`, and
`redirectTo`. `AuthMethodOptions` accepts an exact `redirectTo` and a JSON
object `data`. OTP inputs use `type: "emailOtp" | "magicLink"` (the wire
aliases `"email_otp"` and `"magic_link"` are also accepted). OAuth input is
`{ provider, options?: { redirectTo?, skipBrowserRedirect? } }`.

`Session` contains the short-lived `access_token`, rotating opaque
`refresh_token`, `token_type: "bearer"`, `expires_in`, `expires_at`, and the
identity-safe `user`. The client does not expose credential hashes, provider
access tokens, or refresh-token storage internals.

### Auth state events

`onAuthStateChange` emits `INITIAL_SESSION`, `SIGNED_IN`, `SIGNED_OUT`,
`TOKEN_REFRESHED`, `USER_UPDATED`, or `PASSWORD_RECOVERY`, with a `Session`
or `null`. Events are local to the client and may be propagated between browser
contexts through `BroadcastChannel` or the storage-event fallback. They are
not a server-side audit stream.

## Browser and server use

The root client contains no Node-only imports and works in a browser, a Node
runtime with `fetch`, or a test runtime. For Next.js, the optional adapter
entrypoints provide the intended lifecycle:

```ts
import { createBrowserClient } from "mrjim-auth/nextjs";
import { createServerClient } from "mrjim-auth/nextjs/server";

const browserClient = createBrowserClient(
  "https://example.test/auth/v1",
  "publishable-key",
  { auth: { storageKey: "web" } },
);

declare const requestCookies: {
  getAll(): readonly { name: string; value: string }[];
  setAll(values: readonly { name: string; value: string; options: Record<string, unknown> }[]): void;
};

const requestClient = createServerClient(
  "https://example.test/auth/v1",
  "publishable-key",
  {
    cookies: requestCookies,
    auth: { storageKey: "web" },
  },
);

void browserClient.auth;
void requestClient.auth;
```

`createBrowserClient` reuses one client per module realm and storage key. A
conflicting URL, key, fetch, storage, lock, or auth configuration throws.
`createServerClient` must be created per request and uses cookie-backed storage;
it forces `persistSession: true`, `detectSessionInUrl: false`, and
`autoRefreshToken: false`. Cookie reads remain advisory, and cookie writes
must be available for operations that rotate or clear a session.

For a framework-neutral server, pass the resulting `AuthServer` to the
Express adapter. See the server and framework guides for HTTP setup.

## Security boundaries

Use publishable keys only in browser or user-session clients. Keep secret API
keys, signing keys, token-hash keys, encryption keys, database credentials,
and `createAdminClient` in trusted server code. Authorization must be checked
by the project backend; `getPermissions` and client metadata are not an
authorization boundary.

The package has no mandatory hosted service or paid dependency. The client only
needs the project's HTTP endpoint and a project-selected storage/fetch
environment.
