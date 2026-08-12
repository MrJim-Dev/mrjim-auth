"use client";

import { useState } from "react";

interface OAuthPayload {
  readonly data?: { readonly url?: string } | null;
  readonly error?: { readonly message?: string } | null;
}

/** Starts OAuth through a Route Handler so the server cookie holds the PKCE verifier. */
export function GoogleOAuthButton() {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function start() {
    setBusy(true);
    setMessage(null);
    try {
      const response = await fetch("/api/auth/google", { method: "POST" });
      const payload = await response.json() as OAuthPayload;
      if (!response.ok || payload.data?.url === undefined) {
        setMessage(payload.error?.message ?? "Google sign-in is unavailable");
        return;
      }
      window.location.assign(payload.data.url);
    } catch {
      setMessage("Google sign-in is unavailable");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="oauth-block">
      <div className="divider"><span>or</span></div>
      <button className="secondary-button" disabled={busy} onClick={start} type="button">{busy ? "Redirecting…" : "Continue with Google"}</button>
      {message === null ? null : <p aria-live="polite" className="notice">{message}</p>}
    </div>
  );
}
