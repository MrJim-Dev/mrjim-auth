# Sessions

An authenticated session contains a short-lived ES256 access token and a
rotating opaque refresh token. PostgreSQL stores refresh-token hashes and session
family state; raw refresh tokens exist only at the client/server exchange edge.

```ts compile
import { createClient, type Session } from "mrjim-auth";

const client = createClient("https://app.example.com/auth/v1", "public-key");

export async function restore(session: Session) {
  const { data, error } = await client.auth.setSession(session);
  if (error) throw error;
  return data.session;
}
```

## Rotation and replay

`refreshSession()` consumes one refresh token and returns a replacement. The
browser client serializes refreshes across tabs with Web Locks when available
and a bounded fallback lock otherwise. Cross-tab messages contain only revision
signals, never tokens. A replay or invalid family state is rejected by the
server.

## Browser lifecycle

`persistSession`, `autoRefreshToken`, and `detectSessionInUrl` default to the
client policy. `startAutoRefresh()` and `stopAutoRefresh()` control scheduling;
`dispose()` releases timers, listeners, channels, and in-flight work. Use a
unique `storageKey` per auth endpoint in one origin.

Auth events are ordered locally. `INITIAL_SESSION`, sign-in, refresh, recovery,
user-update, and sign-out events are notifications—not authorization evidence.

## Server rendering

Create one fresh server client per request with a cookie adapter. Cookie-derived
`getSession()` is advisory. Before rendering private data or making an
authorization decision, call `getUser()` or verify the access token at the
backend boundary. Never cache a request-local server client globally.

## Sign-out scopes

- `local` revokes the current session.
- `others` revokes the user's other sessions.
- `global` revokes all sessions for the user.

Revocation is authoritative in PostgreSQL. An already issued access token may
remain cryptographically valid until its short expiry unless your project adds
an online revocation check.
