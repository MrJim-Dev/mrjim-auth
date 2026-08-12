import Link from "next/link";
import { getServerAuthState } from "../lib/server-auth";
import { navigationForPermissions } from "../lib/navigation";

export async function Navigation() {
  const { user, permissions } = await getServerAuthState();
  const items = navigationForPermissions(permissions);

  return (
    <header className="site-header">
      <Link className="brand" href="/">mrjim-auth demo</Link>
      <nav aria-label="Primary navigation" className="nav-links">
        {items.map((item) => <Link href={item.href} key={item.href}>{item.label}</Link>)}
        {user === null ? (
          <>
            <Link href="/login">Sign in</Link>
            <Link href="/recover">Forgot password?</Link>
          </>
        ) : (
          <form action="/auth/logout" method="post">
            <button className="link-button" type="submit">Sign out</button>
          </form>
        )}
      </nav>
    </header>
  );
}
