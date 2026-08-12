import { redirect } from "next/navigation";
import { getServerAuthState } from "../../lib/server-auth";

export const dynamic = "force-dynamic";

export default async function ProfilePage() {
  const { user, permissions } = await getServerAuthState();
  if (user === null) {
    redirect("/login");
    return null;
  }

  const displayName = typeof user.user_metadata.display_name === "string"
    ? user.user_metadata.display_name
    : user.email ?? "Authenticated user";

  return (
    <section>
      <p className="small">Server-rendered profile</p>
      <h1>{displayName}</h1>
      <p className="muted">This page authorized the request with <code>auth.getUser()</code>, which validates the bearer session with the auth backend.</p>
      <div className="profile-grid">
        <div className="card">
          <dl>
            <dt>User ID</dt>
            <dd>{user.id}</dd>
          </dl>
        </div>
        <div className="card">
          <dl>
            <dt>Email</dt>
            <dd>{user.email ?? "Not set"}</dd>
          </dl>
        </div>
        <div className="card">
          <dl>
            <dt>Confirmed</dt>
            <dd>{user.confirmed_at === null ? "Pending" : "Yes"}</dd>
          </dl>
        </div>
      </div>
      <div className="card" style={{ marginTop: "1rem" }}>
        <h2>Effective permissions</h2>
        {permissions.length === 0 ? <p className="muted">No permissions assigned.</p> : (
          <ul className="permission-list">
            {permissions.map((permission) => <li key={permission}>{permission}</li>)}
          </ul>
        )}
      </div>
    </section>
  );
}
