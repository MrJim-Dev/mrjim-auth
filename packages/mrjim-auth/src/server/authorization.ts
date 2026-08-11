import { randomUUID } from "node:crypto";
import type {
  AuthRepository,
  RepositoryOperationOptions,
} from "../shared/contracts.js";
import {
  AuthApiError,
  AuthConfigurationError,
  AuthProgrammingError,
} from "../shared/errors.js";
import {
  permissionKeySchema,
  scopeIdentifierSchema,
  type AuthorizationScope,
  type LowercaseKey,
  type UUID,
} from "../shared/types.js";
import type { AuthenticatedSubject } from "./users.js";

/** A permission requirement for an authoritative server-side authorization check. */
export interface AuthorizationRequirement {
  readonly any?: readonly string[];
  readonly all?: readonly string[];
  readonly scope?: AuthorizationScope;
}

/** A request-local subject accepted by the authorization guard. */
export type AuthorizationSubject =
  | (AuthenticatedSubject & { readonly request_id?: string })
  | { readonly user_id: UUID; readonly request_id?: string };

/** Configuration for the server-only authorization service. */
export interface AuthorizationServiceOptions {
  readonly repository: AuthRepository;
  readonly clock?: () => Date;
}

type PermissionCache = Map<string, Promise<readonly string[]>>;

function compareKeys(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function validNow(clock: () => Date): Date {
  const now = clock();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new AuthConfigurationError("authorization clock must return a valid Date");
  }
  return now;
}

/** Parses one canonical lowercase `resource.action` permission key. */
export function normalizePermissionKey(value: unknown): LowercaseKey {
  const parsed = permissionKeySchema.safeParse(value);
  if (!parsed.success) {
    throw new AuthProgrammingError("permission keys must be canonical lowercase resource.action values");
  }
  return parsed.data;
}

function safePermissionKey(value: unknown): string | null {
  const parsed = permissionKeySchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

/**
 * Returns the deterministic specificity of a grant for one required key.
 * Exact grants outrank resource wildcards, which outrank the global wildcard.
 */
export function permissionMatchRank(granted: unknown, required: unknown): number {
  const grant = safePermissionKey(granted);
  const requirement = safePermissionKey(required);
  if (grant === null || requirement === null) return 0;
  if (grant === requirement) return 3;

  const grantSeparator = grant.indexOf(".");
  const requiredSeparator = requirement.indexOf(".");
  const grantResource = grant.slice(0, grantSeparator);
  const grantAction = grant.slice(grantSeparator + 1);
  const requiredResource = requirement.slice(0, requiredSeparator);
  const requiredAction = requirement.slice(requiredSeparator + 1);

  if (
    grantAction === "*" &&
    grantResource === requiredResource &&
    requiredAction !== "*"
  ) {
    return 2;
  }
  if (
    grant === "*.*" &&
    requiredResource !== "*" &&
    requiredAction !== "*"
  ) {
    return 1;
  }
  return 0;
}

/** Returns whether one granted permission covers one required permission. */
export function permissionMatches(granted: unknown, required: unknown): boolean {
  return permissionMatchRank(granted, required) > 0;
}

function normalizedScope(scope: AuthorizationScope | undefined): AuthorizationScope | null | undefined {
  if (scope === undefined) return undefined;
  if (scope === null || typeof scope !== "object") return null;
  if (typeof scope.type !== "string" || typeof scope.id !== "string") return null;
  const type = scope.type.trim().toLowerCase();
  const id = scopeIdentifierSchema.safeParse(scope.id.trim());
  if (type.length === 0 || !id.success) return null;
  return { type, id: id.data };
}

function scopeCacheKey(scope: AuthorizationScope | undefined): string {
  if (scope === undefined) return "global";
  return `scope:${scope.type}\u0000${scope.id}`;
}

function requestId(subject: AuthorizationSubject): string {
  const supplied = subject !== null && typeof subject === "object" ? subject.request_id : undefined;
  if (typeof supplied === "string" && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(supplied)) {
    return supplied;
  }
  return randomUUID();
}

/** Extracts the authenticated user UUID without exposing session internals. */
export function subjectUserId(subject: AuthorizationSubject): UUID | null {
  if (subject === null || typeof subject !== "object") return null;
  if ("user_id" in subject) {
    return typeof subject.user_id === "string" ? subject.user_id : null;
  }
  const userId = subject.session?.user?.id;
  return typeof userId === "string" ? userId : null;
}

function safePermissionRecordKey(permission: unknown): string | null {
  if (permission === null || typeof permission !== "object") return null;
  const candidate = permission as {
    readonly key?: unknown;
    readonly resource?: unknown;
    readonly action?: unknown;
  };
  const key = safePermissionKey(candidate.key);
  if (
    key === null ||
    typeof candidate.resource !== "string" ||
    typeof candidate.action !== "string" ||
    key !== `${candidate.resource}.${candidate.action}`
  ) {
    return null;
  }
  return key;
}

function requirementKeys(values: readonly string[] | undefined): readonly string[] | null | undefined {
  if (values === undefined) return undefined;
  if (!Array.isArray(values) || values.length === 0) return null;
  const normalized = new Set<string>();
  for (const value of values) {
    const key = safePermissionKey(value);
    if (key === null) return null;
    normalized.add(key);
  }
  return [...normalized].sort(compareKeys);
}

function normalizedRequirement(
  requirement: AuthorizationRequirement,
): { readonly any?: readonly string[]; readonly all?: readonly string[]; readonly scope?: AuthorizationScope } | null {
  if (requirement === null || typeof requirement !== "object") return null;
  const any = requirementKeys(requirement.any);
  const all = requirementKeys(requirement.all);
  if (any === null || all === null || (any === undefined && all === undefined)) return null;
  const scope = normalizedScope(requirement.scope);
  if (scope === null) return null;
  return {
    ...(any === undefined ? {} : { any }),
    ...(all === undefined ? {} : { all }),
    ...(scope === undefined ? {} : { scope }),
  };
}

function insufficientPermission(subject: AuthorizationSubject): AuthApiError {
  return new AuthApiError(
    "insufficient_permission",
    403,
    "Insufficient permission",
    requestId(subject),
  );
}

/**
 * Server-only dynamic authorization service.
 *
 * Permission snapshots are cached only by the identity of the request-local
 * subject object. There is no shared permission snapshot keyed by user ID, so
 * a new request object always observes the current database state.
 */
export class AuthorizationService {
  private readonly repository: AuthRepository;
  private readonly clock: () => Date;
  private readonly requestCaches = new WeakMap<object, PermissionCache>();

  constructor(options: AuthorizationServiceOptions) {
    if (
      options.repository === null ||
      typeof options.repository !== "object" ||
      typeof options.repository.authorization?.effectivePermissions !== "function"
    ) {
      throw new AuthConfigurationError("authorization repository is incomplete");
    }
    this.repository = options.repository;
    this.clock = options.clock ?? (() => new Date());
    validNow(this.clock);
  }

  private async resolvePermissions(
    userId: UUID,
    scope: AuthorizationScope | undefined,
  ): Promise<readonly string[]> {
    const normalized = normalizedScope(scope);
    if (normalized === null) return [];
    const options: RepositoryOperationOptions = { now: validNow(this.clock) };
    try {
      const records = await this.repository.authorization.effectivePermissions(
        userId,
        normalized,
        options,
      );
      const permissions = new Set<string>();
      for (const record of records) {
        const key = safePermissionRecordKey(record);
        if (key !== null) permissions.add(key);
      }
      return [...permissions].sort(compareKeys);
    } catch {
      // A missing/corrupt authorization row or an adapter failure must never
      // become access. Returning no grants is the fail-closed result.
      return [];
    }
  }

  private permissionsForSubject(
    subject: AuthorizationSubject,
    scope: AuthorizationScope | undefined,
  ): Promise<readonly string[]> {
    const userId = subjectUserId(subject);
    if (userId === null) return Promise.resolve([]);
    let cache = this.requestCaches.get(subject);
    if (cache === undefined) {
      cache = new Map<string, Promise<readonly string[]>>();
      this.requestCaches.set(subject, cache);
    }
    const key = scopeCacheKey(scope);
    const existing = cache.get(key);
    if (existing !== undefined) return existing;
    const pending = this.resolvePermissions(userId, scope);
    cache.set(key, pending);
    return pending;
  }

  /** Resolves normalized effective permission keys for a user and optional scope. */
  async getPermissions(userId: UUID, scope?: AuthorizationScope): Promise<readonly string[]> {
    return this.resolvePermissions(userId, scope);
  }

  /**
   * Authorizes a request-local subject and returns that same subject on success.
   * Failure is a stable, redacted 403 with a bounded request identifier.
   */
  async authorize<T extends AuthorizationSubject>(
    subject: T,
    requirement: AuthorizationRequirement,
  ): Promise<T> {
    const normalized = normalizedRequirement(requirement);
    const userId = subjectUserId(subject);
    if (normalized === null || userId === null) {
      throw insufficientPermission(subject);
    }
    const permissions = await this.permissionsForSubject(subject, normalized.scope);
    const hasAny = normalized.any === undefined || normalized.any.some((required) =>
      permissions.some((granted) => permissionMatches(granted, required)),
    );
    const hasAll = normalized.all === undefined || normalized.all.every((required) =>
      permissions.some((granted) => permissionMatches(granted, required)),
    );
    if (!hasAny || !hasAll) throw insufficientPermission(subject);
    return subject;
  }
}
