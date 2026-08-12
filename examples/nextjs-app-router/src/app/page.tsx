import Link from "next/link";

export default function HomePage() {
  return (
    <section className="hero">
      <p className="small">Project-owned authentication for Node.js</p>
      <h1>Auth that stays with your app.</h1>
      <p>
        This free, self-hosted Next.js App Router example keeps the auth API and
        PostgreSQL database under the project&apos;s control. Try password auth,
        Google OAuth, recovery, SSR profile rendering, permissions, and logout.
      </p>
      <div className="actions">
        <Link className="primary-button" href="/login">Sign in or create an account</Link>
        <Link className="secondary-button" href="/profile">View the protected profile</Link>
      </div>
    </section>
  );
}
