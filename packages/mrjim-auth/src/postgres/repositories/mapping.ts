import {
  lowercaseKeySchema,
  oauthFlowSchema,
  permissionKeySchema,
  redactedMetadataSchema,
  roleKeySchema,
  safeIdentityDataSchema,
  type Identity,
  type Permission,
  type Role,
  type User,
} from "../../shared/types.js";
import type {
  ApiKeyRecord,
  OAuthStateRecord,
  OneTimeTokenInput,
  RefreshTokenRecord,
  SessionRecord,
} from "../../shared/contracts.js";
import type { Selectable } from "kysely";
import type {
  ApiKeysTable,
  IdentitiesTable,
  OAuthStatesTable,
  OneTimeTokensTable,
  PermissionsTable,
  RefreshTokensTable,
  RolesTable,
  SessionsTable,
  UsersTable,
} from "./schema.js";

function iso(value: Date): string {
  return value.toISOString();
}

function nullableIso(value: Date | null): string | null {
  return value === null ? null : iso(value);
}

function copyBytes(value: Buffer): Uint8Array {
  return Uint8Array.from(value);
}

function firstConfirmation(...values: readonly (Date | null)[]): string | null {
  const confirmed = values.filter((value): value is Date => value !== null);
  if (confirmed.length === 0) return null;
  confirmed.sort((left, right) => left.getTime() - right.getTime());
  const first = confirmed[0];
  return first === undefined ? null : iso(first);
}

/** Map a typed database user row to the Supabase-shaped safe user contract. */
export function mapUser(row: Selectable<UsersTable>): User {
  return {
    id: row.id,
    email: row.email,
    phone: row.phone,
    email_confirmed_at: nullableIso(row.email_confirmed_at),
    phone_confirmed_at: nullableIso(row.phone_confirmed_at),
    confirmed_at: firstConfirmation(row.email_confirmed_at, row.phone_confirmed_at),
    last_sign_in_at: nullableIso(row.last_sign_in_at),
    banned_until: nullableIso(row.banned_until),
    user_metadata: row.user_metadata,
    app_metadata: row.app_metadata,
    created_at: iso(row.created_at),
    updated_at: iso(row.updated_at),
    deleted_at: nullableIso(row.deleted_at),
  };
}

/** Map a typed identity row while validating the public identity allowlist. */
export function mapIdentity(row: Selectable<IdentitiesTable>): Identity {
  return {
    id: row.id,
    user_id: row.user_id,
    provider: row.provider,
    provider_subject: row.provider_subject,
    email: row.email,
    identity_data: safeIdentityDataSchema.parse(row.identity_data),
    created_at: iso(row.created_at),
    updated_at: iso(row.updated_at),
  };
}

/** Map a typed session row to the internal durable session contract. */
export function mapSession(row: Selectable<SessionsTable>): SessionRecord {
  return {
    id: row.id,
    user_id: row.user_id,
    aal: row.aal,
    ip_address: row.ip_address,
    user_agent: row.user_agent,
    created_at: row.created_at,
    refreshed_at: row.refreshed_at,
    expires_at: row.expires_at,
    revoked_at: row.revoked_at,
  };
}

/** Map a typed refresh-token row without reconstituting a raw bearer token. */
export function mapRefreshToken(row: Selectable<RefreshTokensTable>): RefreshTokenRecord {
  return {
    id: row.id,
    session_id: row.session_id,
    token_hash: copyBytes(row.token_hash),
    family_id: row.family_id,
    parent_id: row.parent_id,
    replacement_id: row.replacement_id,
    issued_at: row.issued_at,
    used_at: row.used_at,
    expires_at: row.expires_at,
    revoked_at: row.revoked_at,
  };
}

/** Map the deliberately narrow return shape of a consumed one-time token. */
export function mapConsumedOneTimeToken(
  row: Pick<Selectable<OneTimeTokensTable>, "user_id" | "purpose" | "target" | "redirect" | "metadata" | "expires_at">,
): Omit<OneTimeTokenInput, "token_hash"> {
  return {
    user_id: row.user_id,
    purpose: row.purpose as OneTimeTokenInput["purpose"],
    target: row.target,
    redirect: row.redirect,
    metadata: redactedMetadataSchema.parse(row.metadata),
    expires_at: row.expires_at,
  };
}

/** Map a typed OAuth state row for server-side callback orchestration. */
export function mapOAuthState(
  row: Pick<Selectable<OAuthStatesTable>, "id" | "state_hash" | "provider" | "flow" | "pkce_challenge" | "encrypted_verifier" | "redirect_target" | "linking_user_id" | "expires_at" | "consumed_at">,
): OAuthStateRecord {
  return {
    id: row.id,
    state_hash: copyBytes(row.state_hash),
    provider: row.provider,
    flow: oauthFlowSchema.parse(row.flow),
    pkce_challenge: row.pkce_challenge,
    encrypted_verifier: row.encrypted_verifier === null ? null : copyBytes(row.encrypted_verifier),
    redirect: row.redirect_target,
    linking_user_id: row.linking_user_id,
    expires_at: row.expires_at,
    consumed_at: row.consumed_at,
  };
}

/** Map a typed role row through the shared lowercase-key validator. */
export function mapRole(row: Selectable<RolesTable>): Role {
  return {
    id: row.id,
    key: roleKeySchema.parse(row.key),
    name: row.name,
    description: row.description,
    rank: row.rank,
    is_system: row.is_system,
    created_at: iso(row.created_at),
    updated_at: iso(row.updated_at),
  };
}

/** Map a typed permission row through the shared key/resource validators. */
export function mapPermission(row: Selectable<PermissionsTable>): Permission {
  return {
    id: row.id,
    key: permissionKeySchema.parse(row.key),
    resource: lowercaseKeySchema.parse(row.resource),
    action: lowercaseKeySchema.parse(row.action),
    description: row.description,
    created_at: iso(row.created_at),
    updated_at: iso(row.updated_at),
  };
}

/** Map an API-key row without a raw key value. */
export function mapApiKey(
  row: Pick<Selectable<ApiKeysTable>, "id" | "prefix" | "key_hash" | "kind" | "scopes" | "expires_at" | "revoked_at">,
): ApiKeyRecord {
  return {
    id: row.id,
    prefix: row.prefix,
    kind: row.kind,
    scopes: [...row.scopes],
    key_hash: copyBytes(row.key_hash),
    expires_at: row.expires_at,
    revoked_at: row.revoked_at,
  };
}
