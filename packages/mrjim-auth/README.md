# mrjim-auth

Project-owned Node.js/PostgreSQL authentication and S3 object storage with a
Supabase-shaped browser client, a Node-only admin client, clean `auth`
migrations, OAuth/OIDC, rotating sessions, dynamic roles/permissions, and
Express/Next.js adapters.

See the repository documentation for the five-minute setup, API/schema
reference, security checklist, compatibility matrix, and runnable examples.

Runtime support: Node.js 24+ and PostgreSQL 15-17. PostgreSQL 18 validation is
required before using the package on the current Courtera target. The package is ESM-only and
has no Supabase runtime, central MrJim auth host, or mandatory paid/hosted
service dependency. Next.js projects can mount the server in their own App
Router with `mrjim-auth/nextjs/route`.
