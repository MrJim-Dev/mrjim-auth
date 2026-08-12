"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { GoogleOAuthButton } from "./GoogleOAuthButton";

type Mode = "login" | "signup";
interface AuthPayload {
  readonly data?: { readonly authenticated?: boolean } | null;
  readonly error?: { readonly message?: string } | null;
}

export function AuthForm() {
  const router = useRouter();
  const [mode, setMode] = useState<Mode>("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      const response = await fetch("/api/auth/password", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode, email, password }),
      });
      const payload = await response.json() as AuthPayload;
      if (!response.ok) {
        setMessage(payload.error?.message ?? "Authentication failed");
        return;
      }
      if (payload.data?.authenticated === true) {
        router.push("/profile");
        router.refresh();
        return;
      }
      setMessage("Account created. Check your email before signing in.");
    } catch {
      setMessage("The auth service is unavailable. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card auth-card">
      <div className="segmented" role="tablist" aria-label="Authentication mode">
        <button className={mode === "login" ? "selected" : ""} onClick={() => setMode("login")} role="tab" type="button">Sign in</button>
        <button className={mode === "signup" ? "selected" : ""} onClick={() => setMode("signup")} role="tab" type="button">Create account</button>
      </div>
      <h1>{mode === "login" ? "Welcome back" : "Create your account"}</h1>
      <p className="muted">This form calls a same-origin Route Handler. The server adapter writes the HttpOnly session cookie.</p>
      <form onSubmit={submit}>
        <label htmlFor="email">Email</label>
        <input autoComplete="email" id="email" onChange={(event) => setEmail(event.target.value)} required type="email" value={email} />
        <label htmlFor="password">Password</label>
        <input autoComplete={mode === "login" ? "current-password" : "new-password"} id="password" minLength={8} onChange={(event) => setPassword(event.target.value)} required type="password" value={password} />
        <button className="primary-button" disabled={busy} type="submit">{busy ? "Working…" : mode === "login" ? "Sign in" : "Create account"}</button>
      </form>
      <GoogleOAuthButton />
      <p className="small"><Link href="/recover">Forgot your password?</Link></p>
      {message === null ? null : <p aria-live="polite" className="notice">{message}</p>}
    </section>
  );
}
