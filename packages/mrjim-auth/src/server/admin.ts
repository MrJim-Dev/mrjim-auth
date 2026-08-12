import {
  AuthApiError,
  AuthConfigurationError,
  AuthProgrammingError,
  isPublicAuthErrorCode,
  type PublicAuthErrorCode,
} from "../shared/errors.js";
import { authFailure, authSuccess, type AuthResult } from "../shared/result.js";
import {
  assertBoundaryObject,
  boundaryDataProperty,
  boundaryOwnDataProperty,
  captureBoundaryFunction,
  captureBoundaryMethodGroup,
  invokeBoundaryResult,
  optionalBoundaryOption,
  requiredBoundaryOption,
} from "./callback-boundary.js";
import { parseJson, snapshotJson, stringifyJson } from "../client/boundary.js";

const adminObjectFreeze = Object.freeze;
const adminObjectCreate = Object.create;
const adminObjectDefineProperty = Object.defineProperty;
const adminObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const adminObjectGetOwnPropertyNames = Object.getOwnPropertyNames;
const adminObjectGetOwnPropertySymbols = Object.getOwnPropertySymbols;
const adminObjectGetPrototypeOf = Object.getPrototypeOf;
const adminObjectHasOwnProperty = Object.prototype.hasOwnProperty;
const adminReflectApply = Reflect.apply;
const adminArrayIsArray = Array.isArray;
const adminArrayPush = Array.prototype.push;
const adminNumberIsSafeInteger = Number.isSafeInteger;
const adminNumberIsFinite = Number.isFinite;
const adminTextEncoder = TextEncoder;
const adminTextDecoder = TextDecoder;
const adminURL = URL;
const adminURLSearchParams = URLSearchParams;
const adminResponse = Response;
const adminResponsePrototype = adminResponse.prototype;
const adminResponseStatusGetter = (() => {
  const descriptor = adminObjectGetOwnPropertyDescriptor(adminResponsePrototype, "status");
  if (descriptor === undefined || typeof descriptor.get !== "function") throw new AuthConfigurationError("Response.status is unavailable");
  return descriptor.get;
})();
const adminResponseBodyGetter = (() => {
  const descriptor = adminObjectGetOwnPropertyDescriptor(adminResponsePrototype, "body");
  if (descriptor === undefined || typeof descriptor.get !== "function") throw new AuthConfigurationError("Response.body is unavailable");
  return descriptor.get;
})();
const MAX_ADMIN_URL = 2048;
const MAX_ADMIN_KEY = 1024;
const MAX_ADMIN_HEADER_COUNT = 128;
const MAX_ADMIN_HEADER_NAME = 128;
const MAX_ADMIN_HEADER_VALUE = 4096;
const MAX_ADMIN_RESPONSE_BYTES = 1024 * 1024;
const MAX_ADMIN_PAGE = 100;
const MAX_ADMIN_ID = 128;

/** The global options accepted by the Node-only admin transport. */
export interface AdminClientGlobalOptions {
  readonly fetch?: typeof fetch;
  readonly headers?: Readonly<Record<string, string>>;
}

/** Fixed configuration captured by {@link createAdminClient}. */
export interface AdminClientOptions {
  readonly global?: AdminClientGlobalOptions;
}

/** Bounded page options used by user and audit administration reads. */
export interface AdminPageOptions {
  readonly page?: number;
  readonly perPage?: number;
}

/** Role-assignment scope accepted by the HTTP admin client. */
export interface AdminScope {
  readonly type: string;
  readonly id: string;
}

/** Public admin namespace returned by the Node-only transport. */
export interface AdminNamespace {
  readonly listUsers: (options?: AdminPageOptions) => Promise<AuthResult<unknown>>;
  readonly getUserById: (userId: string) => Promise<AuthResult<unknown>>;
  readonly findUser: (input: { readonly email: string }) => Promise<AuthResult<unknown>>;
  readonly createUser: (attributes: Readonly<Record<string, unknown>>) => Promise<AuthResult<unknown>>;
  readonly updateUserById: (userId: string, attributes: Readonly<Record<string, unknown>>) => Promise<AuthResult<unknown>>;
  readonly deleteUser: (userId: string, options?: { readonly soft?: boolean }) => Promise<AuthResult<unknown>>;
  readonly inviteUserByEmail: (email: string, options?: Readonly<Record<string, unknown>>) => Promise<AuthResult<unknown>>;
  readonly listRoles: () => Promise<AuthResult<unknown>>;
  readonly createRole: (role: Readonly<Record<string, unknown>>) => Promise<AuthResult<unknown>>;
  readonly updateRole: (roleId: string, patch: Readonly<Record<string, unknown>>) => Promise<AuthResult<unknown>>;
  readonly deleteRole: (roleId: string) => Promise<AuthResult<unknown>>;
  readonly setRolePermissions: (roleId: string, permissionIds: readonly string[]) => Promise<AuthResult<unknown>>;
  readonly setRoleInheritance: (roleId: string, inheritedRoleIds: readonly string[]) => Promise<AuthResult<unknown>>;
  readonly assignRole: (userId: string, roleId: string, scope?: AdminScope | null) => Promise<AuthResult<unknown>>;
  readonly unassignRole: (userId: string, roleId: string, scope?: AdminScope | null) => Promise<AuthResult<unknown>>;
  readonly listPermissions: () => Promise<AuthResult<unknown>>;
  readonly createPermission: (permission: Readonly<Record<string, unknown>>) => Promise<AuthResult<unknown>>;
  readonly updatePermission: (permissionId: string, patch: Readonly<Record<string, unknown>>) => Promise<AuthResult<unknown>>;
  readonly deletePermission: (permissionId: string) => Promise<AuthResult<unknown>>;
  readonly listAudit: (options?: AdminPageOptions) => Promise<AuthResult<unknown>>;
}

/** Node-only Supabase-shaped admin client. */
export interface AdminClient {
  readonly auth: Readonly<{ readonly admin: AdminNamespace }>;
}

interface HeaderEntry {
  readonly name: string;
  readonly value: string;
}

interface QueryEntry {
  readonly name: string;
  readonly value: string;
}

function internalError(): AuthResult<never> {
  return frozenFailure(new AuthApiError("internal_error", 500, "Internal authentication error"));
}

function invalidRequest(): AuthResult<never> {
  return frozenFailure(new AuthApiError("invalid_request", 400, "Invalid admin request"));
}

function frozenFailure(error: AuthApiError): AuthResult<never> {
  return adminObjectFreeze(authFailure(error));
}

function frozenSuccess<T>(data: T): AuthResult<T> {
  return adminObjectFreeze(authSuccess(data));
}

function dataProperty(source: object, key: PropertyKey): unknown {
  const property = boundaryOwnDataProperty(source, key);
  if (!property.valid || !property.present) throw new AuthConfigurationError("admin option is malformed");
  return property.value;
}

function optionalDataProperty(source: object, key: PropertyKey): unknown {
  const property = boundaryOwnDataProperty(source, key);
  if (!property.valid) throw new AuthConfigurationError("admin option is malformed");
  return property.present ? property.value : undefined;
}

function validString(value: unknown, label: string, maximum: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) throw new AuthProgrammingError(`${label} is malformed`);
  if (value.trim() !== value || /[\u0000-\u001f\u007f-\u009f]/u.test(value)) throw new AuthProgrammingError(`${label} is malformed`);
  return value;
}

function validBaseUrl(value: unknown): string {
  const raw = validString(value, "auth URL", MAX_ADMIN_URL);
  let parsed: URL;
  try {
    parsed = new adminURL(raw);
  } catch {
    throw new AuthConfigurationError("auth URL is malformed");
  }
  if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.username !== "" || parsed.password !== "" || parsed.search !== "" || parsed.hash !== "") {
    throw new AuthConfigurationError("auth URL is malformed");
  }
  return raw.replace(/\/+$/u, "");
}

function headerName(value: string): string {
  if (value.length === 0 || value.length > MAX_ADMIN_HEADER_NAME || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(value)) {
    throw new AuthConfigurationError("admin headers are malformed");
  }
  return value.toLowerCase();
}

function isBrowserHeader(name: string): boolean {
  return name === "origin" || name === "referer" || name === "cookie" || name.startsWith("sec-fetch-");
}

function isSecurityHeader(name: string): boolean {
  return name === "apikey" || name === "authorization" || name === "content-type" || name === "accept";
}

function snapshotHeaders(value: unknown): readonly HeaderEntry[] {
  if (value === undefined) return adminObjectFreeze([] as HeaderEntry[]);
  assertBoundaryObject(value, "admin global headers");
  const source = value as object;
  let names: string[];
  try {
    names = adminObjectGetOwnPropertyNames(source);
    if (adminObjectGetOwnPropertySymbols(source).length !== 0 || names.length > MAX_ADMIN_HEADER_COUNT) throw new Error("invalid");
  } catch {
    throw new AuthConfigurationError("admin global headers are malformed");
  }
  const output: HeaderEntry[] = [];
  for (let index = 0; index < names.length; index += 1) {
    const nameValue = names[index];
    if (nameValue === undefined) throw new AuthConfigurationError("admin global headers are malformed");
    const normalizedName = headerName(nameValue);
    const property = boundaryOwnDataProperty(source, nameValue);
    if (!property.valid || !property.present || typeof property.value !== "string" || property.value.length > MAX_ADMIN_HEADER_VALUE || /[\r\n]/u.test(property.value)) {
      throw new AuthConfigurationError("admin global headers are malformed");
    }
    if (isBrowserHeader(normalizedName)) throw new AuthConfigurationError("browser origin/fetch headers are not allowed for the admin client");
    if (isSecurityHeader(normalizedName)) continue;
    adminReflectApply(adminArrayPush, output, [adminObjectFreeze({ name: normalizedName, value: property.value })]);
  }
  return adminObjectFreeze(output);
}

function validId(value: unknown, label: string): string {
  const id = validString(value, label, MAX_ADMIN_ID);
  if (id.includes("/") || id.includes("\\") || id.includes("?") || id.includes("#")) throw new AuthProgrammingError(`${label} is malformed`);
  return id;
}

function pageOptions(value: unknown): { readonly page: number; readonly perPage: number } {
  if (value === undefined) return { page: 1, perPage: 50 };
  if (value === null || typeof value !== "object" || adminArrayIsArray(value)) throw new AuthProgrammingError("admin page options are malformed");
  const source = value as object;
  assertBoundaryObject(source, "admin page options");
  const pageValue = optionalDataProperty(source, "page");
  const perPageValue = optionalDataProperty(source, "perPage");
  const page = pageValue === undefined ? 1 : pageValue;
  const perPage = perPageValue === undefined ? 50 : perPageValue;
  if (!adminNumberIsSafeInteger(page) || (page as number) < 1 || (page as number) > MAX_ADMIN_PAGE || !adminNumberIsSafeInteger(perPage) || (perPage as number) < 1 || (perPage as number) > MAX_ADMIN_PAGE) {
    throw new AuthProgrammingError("admin page options are malformed");
  }
  return { page: page as number, perPage: perPage as number };
}

function bodyObject(value: unknown, label: string): Readonly<Record<string, unknown>> {
  const snapshot = snapshotJson(value, label);
  if (snapshot === null || typeof snapshot !== "object" || adminArrayIsArray(snapshot)) throw new AuthProgrammingError(`${label} is malformed`);
  return snapshot as Readonly<Record<string, unknown>>;
}

function idList(value: unknown, label: string): readonly string[] {
  const snapshot = snapshotJson(value, label);
  if (!adminArrayIsArray(snapshot) || snapshot.length > 1000) throw new AuthProgrammingError(`${label} is malformed`);
  const output: string[] = [];
  for (let index = 0; index < snapshot.length; index += 1) {
    const id = validId(snapshot[index], `${label}[${index}]`);
    if (output.includes(id)) throw new AuthProgrammingError(`${label} contains duplicates`);
    adminReflectApply(adminArrayPush, output, [id]);
  }
  return adminObjectFreeze(output);
}

function scopeValue(value: AdminScope | null | undefined): Readonly<Record<string, unknown>> | null {
  if (value === undefined || value === null) return null;
  const source = bodyObject(value, "admin scope");
  const type = validString(source.type, "admin scope type", 64);
  const id = validString(source.id, "admin scope id", 256);
  return adminObjectFreeze({ type, id });
}

function responseStatus(response: object): number {
  try {
    if (adminObjectGetPrototypeOf(response) === adminResponsePrototype) {
      const status = adminReflectApply(adminResponseStatusGetter, response, []) as unknown;
      if (typeof status !== "number" || !adminNumberIsSafeInteger(status) || status < 100 || status > 599) throw new Error("invalid");
      return status;
    }
    const status = boundaryOwnDataProperty(response, "status");
    if (!status.valid || !status.present || typeof status.value !== "number" || !adminNumberIsSafeInteger(status.value) || status.value < 100 || status.value > 599) throw new Error("invalid");
    return status.value;
  } catch {
    throw new Error("invalid response status");
  }
}

async function readNativeResponseBody(response: object): Promise<string> {
  let stream: unknown;
  try {
    stream = adminReflectApply(adminResponseBodyGetter, response, []);
  } catch {
    throw new Error("invalid response body");
  }
  if (stream === null) return "";
  if (stream === undefined || typeof stream !== "object") throw new Error("invalid response body");
  const readerProperty = boundaryDataProperty(stream, "getReader");
  if (!readerProperty.valid || !readerProperty.present || typeof readerProperty.value !== "function") throw new Error("invalid response body");
  const reader = adminReflectApply(readerProperty.value, stream, []) as unknown;
  if (reader === null || typeof reader !== "object") throw new Error("invalid response reader");
  const readProperty = boundaryDataProperty(reader, "read");
  const releaseProperty = boundaryDataProperty(reader, "releaseLock");
  if (!readProperty.valid || !readProperty.present || typeof readProperty.value !== "function" || !releaseProperty.valid || !releaseProperty.present || typeof releaseProperty.value !== "function") throw new Error("invalid response reader");
  const decoder = new adminTextDecoder("utf-8", { fatal: true });
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const item = await invokeBoundaryResult<unknown>(readProperty.value, reader, [], "admin response reader");
      if (item === null || typeof item !== "object") throw new Error("invalid response chunk");
      const done = boundaryOwnDataProperty(item, "done");
      const value = boundaryOwnDataProperty(item, "value");
      if (!done.valid || !done.present || typeof done.value !== "boolean" || !value.valid || !value.present) throw new Error("invalid response chunk");
      if (done.value) break;
      if (!(value.value instanceof Uint8Array)) throw new Error("invalid response chunk");
      total += value.value.byteLength;
      if (!adminNumberIsSafeInteger(total) || total > MAX_ADMIN_RESPONSE_BYTES) throw new Error("response is oversized");
      adminReflectApply(adminArrayPush, chunks, [Uint8Array.from(value.value)]);
    }
    let combined = new Uint8Array(total);
    let offset = 0;
    for (let index = 0; index < chunks.length; index += 1) {
      const chunk = chunks[index];
      if (chunk === undefined) throw new Error("invalid response chunks");
      combined.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return decoder.decode(combined);
  } finally {
    try { adminReflectApply(releaseProperty.value, reader, []); } catch { /* bounded read already failed or completed */ }
  }
}

async function readResponseBody(response: object): Promise<string> {
  if (adminObjectGetPrototypeOf(response) === adminResponsePrototype) return readNativeResponseBody(response);
  const textMethod = captureBoundaryMethodGroup(response, "admin response", ["text"]).text as (...args: unknown[]) => unknown;
  const text = await invokeBoundaryResult<unknown>(textMethod, response, [], "admin response.text");
  if (typeof text !== "string" || !adminNumberIsFinite(new adminTextEncoder().encode(text).byteLength) || new adminTextEncoder().encode(text).byteLength > MAX_ADMIN_RESPONSE_BYTES) throw new Error("response is oversized");
  return text;
}

function stableMessage(code: PublicAuthErrorCode): string {
  switch (code) {
    case "invalid_request": return "Invalid request";
    case "invalid_credentials": return "Invalid credentials";
    case "unauthorized": return "Authentication required";
    case "forbidden": return "Forbidden";
    case "insufficient_permission": return "Insufficient permission";
    case "not_found": return "Not found";
    case "conflict": return "Conflict";
    case "invalid_token": return "Invalid token";
    case "token_expired": return "Token expired";
    case "refresh_token_reused": return "Refresh token reused";
    case "session_expired": return "Session expired";
    case "otp_invalid": return "Invalid one-time code";
    case "otp_expired": return "One-time code expired";
    case "otp_attempts_exceeded": return "One-time code attempts exceeded";
    case "rate_limit_exceeded": return "Rate limit exceeded";
    case "redirect_not_allowed": return "Redirect is not allowed";
    case "oauth_state_invalid": return "OAuth state is invalid";
    case "oauth_provider_error": return "OAuth provider error";
    case "identity_already_linked": return "Identity is already linked";
    case "identity_unlink_not_allowed": return "Identity cannot be unlinked";
    case "internal_error": return "Internal authentication error";
    default: return "Internal authentication error";
  }
}

function requestId(value: unknown, secretKey: string): string | undefined {
  if (typeof value !== "string" || value.length < 1 || value.length > 128 || !/^[A-Za-z0-9_-]+$/u.test(value)) return undefined;
  if (value === secretKey || value.includes(secretKey)) return undefined;
  return value;
}

function parsedError(status: number, body: unknown, secretKey: string): AuthResult<never> {
  if (body === null || typeof body !== "object" || adminArrayIsArray(body)) return internalError();
  const errorProperty = boundaryOwnDataProperty(body, "error");
  if (!errorProperty.valid || !errorProperty.present || errorProperty.value === null || typeof errorProperty.value !== "object" || adminArrayIsArray(errorProperty.value)) return internalError();
  const source = errorProperty.value as object;
  const codeProperty = boundaryOwnDataProperty(source, "code");
  const requestIdProperty = boundaryOwnDataProperty(source, "request_id");
  const code = codeProperty.valid && codeProperty.present && isPublicAuthErrorCode(codeProperty.value) ? codeProperty.value : "internal_error";
  const safeStatus = status >= 400 && status <= 599 ? status : 500;
  const id = requestIdProperty.valid && requestIdProperty.present ? requestId(requestIdProperty.value, secretKey) : undefined;
  return frozenFailure(new AuthApiError(code, safeStatus, stableMessage(code), id));
}

function queryUrl(baseUrl: string, path: string, entries: readonly QueryEntry[] = []): string {
  const url = new adminURL(`${baseUrl}${path}`);
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry === undefined) throw new AuthProgrammingError("admin query is malformed");
    url.searchParams.set(entry.name, entry.value);
  }
  return url.toString();
}

function pageQuery(value: unknown): readonly QueryEntry[] {
  const page = pageOptions(value);
  return adminObjectFreeze([
    adminObjectFreeze({ name: "page", value: String(page.page) }),
    adminObjectFreeze({ name: "per_page", value: String(page.perPage) }),
  ]);
}

function scopeQuery(value: AdminScope | null | undefined): readonly QueryEntry[] {
  const scope = scopeValue(value);
  if (scope === null) return [];
  return adminObjectFreeze([
    adminObjectFreeze({ name: "scope_type", value: String(scope.type) }),
    adminObjectFreeze({ name: "scope_id", value: String(scope.id) }),
  ]);
}

/**
 * Creates a Node-only immutable admin client. The secret key, fetch callback,
 * URL, and headers are captured once and are never placed on the returned
 * object or in error messages.
 */
export function createAdminClient(authUrl: string, secretKey: string, options?: AdminClientOptions): AdminClient {
  const baseUrl = validBaseUrl(authUrl);
  const key = validString(secretKey, "admin secret key", MAX_ADMIN_KEY);
  if (options !== undefined) assertBoundaryObject(options, "admin client options");
  const root = options as unknown as object | undefined;
  const globalValue = root === undefined ? undefined : optionalBoundaryOption(root, "global", "admin global options");
  const globalRecord = globalValue === undefined ? undefined : (() => {
    assertBoundaryObject(globalValue, "admin global options");
    return globalValue as object;
  })();
  const fetchValue = globalRecord === undefined ? globalThis.fetch : optionalBoundaryOption(globalRecord, "fetch", "admin global fetch");
  const fetcher = captureBoundaryFunction(fetchValue, "admin global fetch") as typeof globalThis.fetch;
  const headersValue = globalRecord === undefined ? undefined : optionalBoundaryOption(globalRecord, "headers", "admin global headers");
  const customHeaders = snapshotHeaders(headersValue);

  const request = async (
    method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
    path: string,
    query: readonly QueryEntry[] = [],
    body?: unknown,
  ): Promise<AuthResult<unknown>> => {
    let url: string;
    let serializedBody: string | undefined;
    try {
      url = queryUrl(baseUrl, path, query);
      if (body !== undefined) serializedBody = stringifyJson(snapshotJson(body, "admin request body"), "admin request body");
    } catch (error) {
      if (error instanceof AuthProgrammingError) return invalidRequest();
      return internalError();
    }
    const requestHeaders: Record<string, string> = adminObjectCreate(null) as Record<string, string>;
    for (let index = 0; index < customHeaders.length; index += 1) {
      const entry = customHeaders[index];
      if (entry === undefined) continue;
      adminObjectDefineProperty(requestHeaders, entry.name, { configurable: true, enumerable: true, writable: true, value: entry.value });
    }
    adminObjectDefineProperty(requestHeaders, "apikey", { configurable: true, enumerable: true, writable: true, value: key });
    adminObjectDefineProperty(requestHeaders, "accept", { configurable: true, enumerable: true, writable: true, value: "application/json" });
    if (serializedBody !== undefined) adminObjectDefineProperty(requestHeaders, "content-type", { configurable: true, enumerable: true, writable: true, value: "application/json" });
    const init: RequestInit = adminObjectFreeze({
      method,
      headers: adminObjectFreeze(requestHeaders),
      ...(serializedBody === undefined ? {} : { body: serializedBody }),
    });
    try {
      const responseValue = await invokeBoundaryResult<unknown>(fetcher, undefined, [url, init], "admin fetch");
      if (responseValue === null || typeof responseValue !== "object") return internalError();
      const response = responseValue as object;
      const status = responseStatus(response);
      const text = await readResponseBody(response);
      if (text.length === 0) {
        if (status >= 200 && status < 300) return frozenSuccess(null);
        return internalError();
      }
      const parsed = parseJson(text, "admin response");
      if (status < 200 || status >= 300) return parsedError(status, parsed, key);
      if (parsed === null || typeof parsed !== "object" || adminArrayIsArray(parsed)) return internalError();
      const dataPropertyValue = boundaryOwnDataProperty(parsed, "data");
      const errorProperty = boundaryOwnDataProperty(parsed, "error");
      if (!dataPropertyValue.valid || !dataPropertyValue.present || !errorProperty.valid || !errorProperty.present) return internalError();
      if (errorProperty.value !== null) return parsedError(status, parsed, key);
      return frozenSuccess(dataPropertyValue.value);
    } catch {
      return internalError();
    }
  };

  const admin: AdminNamespace = {
    listUsers: (optionsValue) => request("GET", "/admin/users", pageQuery(optionsValue)),
    getUserById: (userId) => request("GET", `/admin/users/${encodeURIComponent(validId(userId, "user id"))}`),
    findUser: (input) => {
      const source = bodyObject(input, "find-user input");
      const email = validString(source.email, "user email", 320);
      return request("GET", "/admin/users/find", [{ name: "email", value: email }]);
    },
    createUser: (attributes) => request("POST", "/admin/users", [], bodyObject(attributes, "create-user attributes")),
    updateUserById: (userId, attributes) => request("PATCH", `/admin/users/${encodeURIComponent(validId(userId, "user id"))}`, [], bodyObject(attributes, "update-user attributes")),
    deleteUser: (userId, optionsValue) => {
      const id = validId(userId, "user id");
      if (optionsValue !== undefined && (optionsValue === null || typeof optionsValue !== "object" || adminArrayIsArray(optionsValue))) throw new AuthProgrammingError("delete-user options are malformed");
      const softValue = optionsValue === undefined ? true : optionalDataProperty(optionsValue as object, "soft");
      if (softValue !== undefined && typeof softValue !== "boolean") throw new AuthProgrammingError("delete-user soft option is malformed");
      if (softValue === false) throw new AuthProgrammingError("hard user deletion is not supported");
      return request("DELETE", `/admin/users/${encodeURIComponent(id)}`, [{ name: "soft", value: "true" }]);
    },
    inviteUserByEmail: (email, optionsValue) => {
      const normalizedEmail = validString(email, "invite email", 320);
      const inviteBody = optionsValue === undefined
        ? adminObjectFreeze({ email: normalizedEmail })
        : adminObjectFreeze({ email: normalizedEmail, options: bodyObject(optionsValue, "invite options") });
      return request("POST", "/admin/users/invite", [], inviteBody);
    },
    listRoles: () => request("GET", "/admin/roles"),
    createRole: (role) => request("POST", "/admin/roles", [], bodyObject(role, "create-role input")),
    updateRole: (roleId, patch) => request("PATCH", `/admin/roles/${encodeURIComponent(validId(roleId, "role id"))}`, [], bodyObject(patch, "update-role patch")),
    deleteRole: (roleId) => request("DELETE", `/admin/roles/${encodeURIComponent(validId(roleId, "role id"))}`),
    setRolePermissions: (roleId, permissionIds) => request("PUT", `/admin/roles/${encodeURIComponent(validId(roleId, "role id"))}/permissions`, [], { permission_ids: idList(permissionIds, "permission ids") }),
    setRoleInheritance: (roleId, inheritedRoleIds) => request("PUT", `/admin/roles/${encodeURIComponent(validId(roleId, "role id"))}/inheritance`, [], { inherited_role_ids: idList(inheritedRoleIds, "inherited role ids") }),
    assignRole: (userId, roleId, scope) => request("PUT", `/admin/users/${encodeURIComponent(validId(userId, "user id"))}/roles/${encodeURIComponent(validId(roleId, "role id"))}`, scopeQuery(scope)),
    unassignRole: (userId, roleId, scope) => request("DELETE", `/admin/users/${encodeURIComponent(validId(userId, "user id"))}/roles/${encodeURIComponent(validId(roleId, "role id"))}`, scopeQuery(scope)),
    listPermissions: () => request("GET", "/admin/permissions"),
    createPermission: (permission) => request("POST", "/admin/permissions", [], bodyObject(permission, "create-permission input")),
    updatePermission: (permissionId, patch) => request("PATCH", `/admin/permissions/${encodeURIComponent(validId(permissionId, "permission id"))}`, [], bodyObject(patch, "update-permission patch")),
    deletePermission: (permissionId) => request("DELETE", `/admin/permissions/${encodeURIComponent(validId(permissionId, "permission id"))}`),
    listAudit: (optionsValue) => request("GET", "/admin/audit", pageQuery(optionsValue)),
  };
  const frozenAdmin = adminObjectFreeze(admin);
  const auth = adminObjectFreeze({ admin: frozenAdmin });
  return adminObjectFreeze({ auth });
}
