"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useState, type FormEvent } from "react";

export function ResetPasswordForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [email, setEmail] = useState(searchParams.get("email") ?? "");
  const [token, setToken] = useState(searchParams.get("token") ?? "");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      const response = await fetch("/api/auth/recovery/reset", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, token, password }),
      });
      const payload = await response.json() as { readonly error?: { readonly message?: string } };
      if (!response.ok) {
        setMessage(payload.error?.message ?? "Password reset failed");
        return;
      }
      setMessage("Password updated. Sign in with your new password.");
      window.setTimeout(() => router.push("/login"), 700);
    } catch {
      setMessage("The auth service is unavailable. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card auth-card">
      <h1>Choose a new password</h1>
      <p className="muted">The recovery email provides the one-time token and email. Keep both bound to this reset.</p>
      <form onSubmit={submit}>
        <label htmlFor="reset-email">Email</label>
        <input autoComplete="email" id="reset-email" onChange={(event) => setEmail(event.target.value)} required type="email" value={email} />
        <label htmlFor="reset-token">Recovery token</label>
        <input id="reset-token" onChange={(event) => setToken(event.target.value)} required type="text" value={token} />
        <label htmlFor="reset-password">New password</label>
        <input autoComplete="new-password" id="reset-password" minLength={8} onChange={(event) => setPassword(event.target.value)} required type="password" value={password} />
        <button className="primary-button" disabled={busy} type="submit">{busy ? "Updating…" : "Update password"}</button>
      </form>
      {message === null ? null : <p aria-live="polite" className="notice">{message}</p>}
      <p className="small"><Link href="/login">Return to sign in</Link></p>
    </section>
  );
}
