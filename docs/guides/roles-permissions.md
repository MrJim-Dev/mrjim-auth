# Roles and permissions

Authorization is dynamic and project-owned. Roles, permissions, inheritance,
and user assignments live in the clean `auth` schema; no Hayahai or shipping
fields are present.

Permission keys use `resource.action`, `resource.*`, or `*.*`. Resources may be
namespaced, for example `invoice.read`, `booking.refund`, or
`auth.roles.manage`. Wildcards are disabled unless server authorization config
explicitly enables them.

## Browser hints

```ts compile
import { createClient } from "mrjim-auth";

const client = createClient("https://app.example.com/auth/v1", "public-key");

export async function mayShowInvoices() {
  const { data, error } = await client.auth.getPermissions();
  return error === null && data.permissions.includes("invoice.read");
}
```

Use that result to shape navigation only. The backend must independently verify
the user/session and enforce `invoice.read` before returning invoice data.

## Administration

The Node-only admin client creates permissions and roles, replaces role
permission sets, defines inheritance, and assigns or unassigns scoped roles.
Administration may authenticate with a project secret API key or a delegated
principal holding `auth.users.manage`, `auth.roles.manage`,
`auth.permissions.manage`, or `auth.audit.read` as appropriate.

Role rank prevents lower-ranked administrators from changing higher-ranked
roles. Protected/system roles cannot be removed in ways that violate the final
administrator-assignment policy. Mutations lock relevant rows and write audit
events in the same transaction.

## Scopes

An assignment may be global or carry `{ type, id }`, such as an organization or
venue. Request authorization must pass the matching scope. Choose scope names
from project vocabulary; the SDK does not impose business-specific columns.

## Suggested seed

- `user`: normal authenticated role with minimum project access.
- `admin`: protected high-rank role with explicit administration permissions.
- `invoice.read`: permission used by the Express example.

Seed idempotently by looking up keys before creation, then set the complete
permission set and assignment deliberately.
