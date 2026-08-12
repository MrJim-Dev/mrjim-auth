# Google OAuth

Google OAuth uses Authorization Code with PKCE S256. The browser creates and
stores the verifier; Google credentials stay on the auth server.

## Google Console configuration

Create a Web application OAuth client and register this exact redirect URI:

```text
https://api.example.com/auth/v1/oauth/callback/google
```

Set `oauth.google.clientId` and `oauth.google.clientSecret` only in server
configuration. Add the application's final redirect, such as
`https://app.example.com/auth/callback`, to `redirects.allowed`.

## Start sign-in

```ts compile
import { createClient } from "mrjim-auth";

const client = createClient("https://api.example.com/auth/v1", "public-key");

export async function signInWithGoogle() {
  const result = await client.auth.signInWithOAuth({
    provider: "google",
    options: { redirectTo: "https://app.example.com/auth/callback" },
  });
  if (result.error) throw result.error;
  return result.data.url;
}
```

By default the browser client navigates to the provider. Set
`skipBrowserRedirect: true` when your UI must perform navigation itself.

## Callback

Mount the auth server at the configured base URL. It validates state, nonce,
issuer, audience, provider code, and PKCE binding before creating or linking an
identity. The application callback then lets the browser client detect the
returned authorization code or explicitly calls `exchangeCodeForSession(code)`.

Do not log callback URLs, codes, state, nonce, provider tokens, or PKCE values.
Use HTTPS in production and keep redirect allowlists exact—wildcards are
rejected.
