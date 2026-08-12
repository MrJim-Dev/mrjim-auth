# Email and password

## Sign up and sign in

```ts compile
import { createClient } from "mrjim-auth";

const client = createClient("https://app.example.com/auth/v1", "public-key");

export async function register(email: string, password: string) {
  return client.auth.signUp({
    email,
    password,
    options: {
      redirectTo: "https://app.example.com/auth/confirm",
      data: { source: "website" },
    },
  });
}

export async function login(email: string, password: string) {
  return client.auth.signInWithPassword({ email, password });
}
```

Redirects must exactly match the server allowlist. Signup and recovery responses
do not reveal whether an email already exists. Passwords use the server's
Argon2id policy and are never logged or stored in plaintext.

## Forgot password

```ts compile
import { createClient } from "mrjim-auth";

const client = createClient("https://app.example.com/auth/v1", "public-key");

export async function requestReset(email: string) {
  return client.auth.resetPasswordForEmail(email, {
    redirectTo: "https://app.example.com/auth/recovery",
  });
}

export async function finishReset(email: string, token: string, password: string) {
  return client.auth.resetPassword({
    email,
    token,
    password,
    options: { redirectTo: "https://app.example.com/auth/recovery" },
  });
}
```

Recovery proofs are purpose-bound, single-use, expiry-limited, and consumed in
the same transaction as the credential replacement and session revocation.

## Email OTP and magic links

Call `signInWithOtp({ email, options: { type: "emailOtp" } })` or use
`"magicLink"`, then call `verifyOtp` with the same type and redirect binding.
The project's mail adapter receives a template name and variables and is
responsible for rendering and delivery.
