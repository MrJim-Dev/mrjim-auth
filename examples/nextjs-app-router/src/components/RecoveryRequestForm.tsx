"use client";

import Link from "next/link";
import { useState, type FormEvent } from "react";

export function RecoveryRequestForm() {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      const response = await fetch("/api/auth/recovery/request", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const payload = await response.json() as { readonly error?: { readonly message?: string } };
      setMessage(response.ok ? "If the account exists, a recovery email is on its way." : payload.error?.message ?? "Recovery request failed");
    } catch {
      setMessage("The auth service is unavailable. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card auth-card">
      <h1>Reset your password</h1>
      <p className="muted">We always show the same response so this form does not reveal whether an email is registered.</p>
      <form onSubmit={submit}>
        <label htmlFor="recovery-email">Email</label>
        <input autoComplete="email" id="recovery-email" onChange={(event) => setEmail(event.target.value)} required type="email" value={email} />
        <button className="primary-button" disabled={busy} type="submit">{busy ? "Sending…" : "Email recovery link"}</button>
      </form>
      {message === null ? null : <p aria-live="polite" className="notice">{message}</p>}
      <p className="small"><Link href="/login">Return to sign in</Link></p>
    </section>
  );
}
