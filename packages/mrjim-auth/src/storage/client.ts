import { StorageApiError, StorageProgrammingError, type StorageError } from "./errors.js";
import {
  safeArrayIsArray,
  safeNumberIsSafeInteger,
  safeStringEndsWith,
  safeStringIncludes,
  safeStringReplace,
  safeStringSplit,
  safeStringStartsWith,
  safeStringTrim,
} from "../shared/safe-intrinsics.js";

const MAX_URL_LENGTH = 2_048;
const MAX_KEY_LENGTH = 1_024;
const MAX_TOKEN_LENGTH = 8_192;
const MAX_SIGNED_URL_LENGTH = 16_384;
const MAX_SIGNED_URL_SECONDS = 604_800;

export interface StorageResult<T> {
  readonly data: T | null;
  readonly error: StorageError | null;
}

export interface SignedUrlData {
  readonly signedUrl: string;
}

export interface SignedUploadOptions {
  readonly contentType: string;
  readonly contentLength: number;
  readonly checksumSha256: string;
  readonly cacheControl?: string;
  readonly expiresIn?: number;
}

export interface SignedUploadData extends SignedUrlData {
  readonly requiredHeaders: Readonly<Record<string, string>>;
}

export interface StorageBucketClient {
  readonly createSignedUrl: (path: string, expiresIn: number) => Promise<StorageResult<SignedUrlData>>;
  readonly createSignedUploadUrl: (path: string, options: SignedUploadOptions) => Promise<StorageResult<SignedUploadData>>;
  readonly remove: (paths: readonly string[]) => Promise<StorageResult<null>>;
}

export interface StorageClient {
  readonly from: (bucket: string) => StorageBucketClient;
}

export interface StorageClientOptions {
  readonly accessToken?: (() => string | null | Promise<string | null>) | undefined;
  readonly fetch?: typeof fetch | undefined;
}

function normalizeBaseUrl(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_URL_LENGTH || safeStringTrim(value) !== value) {
    throw new StorageProgrammingError("storage URL is malformed");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new StorageProgrammingError("storage URL is malformed");
  }
  if (
    (parsed.protocol !== "http:" && parsed.protocol !== "https:")
    || parsed.username !== ""
    || parsed.password !== ""
    || parsed.search !== ""
    || parsed.hash !== ""
    || safeStringIncludes(parsed.pathname, "//")
    || /(?:^|\/)\.{1,2}(?:\/|$)|%2f|%2e/iu.test(parsed.pathname)
  ) {
    throw new StorageProgrammingError("storage URL is malformed");
  }
  parsed.pathname = safeStringReplace(parsed.pathname, /\/+$/u, "") || "/";
  return parsed.pathname === "/" ? parsed.origin : parsed.href;
}

function validatePublishableKey(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0 || value.length > 512 || safeStringTrim(value) !== value || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new StorageProgrammingError("publishable key is malformed");
  }
  return value;
}

function validateBucket(value: unknown): string {
  if (typeof value !== "string" || value.length < 3 || value.length > 63 || !/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/u.test(value) || safeStringIncludes(value, "..")) {
    throw new StorageProgrammingError("storage bucket is malformed");
  }
  return value;
}

function validatePath(value: unknown): string {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > MAX_KEY_LENGTH
    || safeStringStartsWith(value, "/")
    || safeStringEndsWith(value, "/")
    || safeStringIncludes(value, "\\")
    || /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new StorageProgrammingError("storage object path is malformed");
  }
  const segments = safeStringSplit(value, "/");
  if (segments === null) throw new StorageProgrammingError("storage object path is malformed");
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index];
    if (segment === "" || segment === "." || segment === "..") {
      throw new StorageProgrammingError("storage object path is malformed");
    }
  }
  return value;
}

function encodePath(value: string): string {
  const segments = safeStringSplit(value, "/");
  if (segments === null) throw new StorageProgrammingError("storage object path is malformed");
  let result = "";
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index];
    if (segment === undefined) throw new StorageProgrammingError("storage object path is malformed");
    result += `${index === 0 ? "" : "/"}${encodeURIComponent(segment)}`;
  }
  return result;
}

function validateExpiresIn(value: unknown): number {
  if (!safeNumberIsSafeInteger(value) || value < 1 || value > MAX_SIGNED_URL_SECONDS) {
    throw new StorageProgrammingError("signed URL lifetime is malformed");
  }
  return value as number;
}

function validateToken(value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_TOKEN_LENGTH || /[\u0000-\u0020\u007f]/u.test(value)) {
    throw new StorageProgrammingError("storage access token is malformed");
  }
  return value;
}

function parseSignedUrl(value: unknown): SignedUrlData | null {
  if (value === null || typeof value !== "object" || safeArrayIsArray(value)) return null;
  const signedUrl = Object.getOwnPropertyDescriptor(value, "signedUrl")?.value;
  if (typeof signedUrl !== "string" || signedUrl.length === 0 || signedUrl.length > MAX_SIGNED_URL_LENGTH) return null;
  try {
    const parsed = new URL(signedUrl);
    if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.username !== "" || parsed.password !== "") return null;
  } catch {
    return null;
  }
  return Object.freeze({ signedUrl });
}

function parseSignedUpload(value: unknown): SignedUploadData | null {
  const signed = parseSignedUrl(value);
  const headersValue = ownValue(value, "requiredHeaders");
  if (signed === null || headersValue === null || typeof headersValue !== "object" || safeArrayIsArray(headersValue)) return null;
  const headers: Record<string, string> = Object.create(null) as Record<string, string>;
  const names = Object.keys(headersValue);
  if (names.length < 1 || names.length > 16) return null;
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index];
    if (name === undefined || !/^[a-z0-9-]+$/u.test(name)) return null;
    const header = ownValue(headersValue, name);
    if (typeof header !== "string" || header.length === 0 || header.length > 4_096 || /[\r\n]/u.test(header)) return null;
    headers[name] = header;
  }
  return Object.freeze({ signedUrl: signed.signedUrl, requiredHeaders: Object.freeze(headers) });
}

function validateSignedUploadOptions(value: unknown): Required<Omit<SignedUploadOptions, "cacheControl">> & { readonly cacheControl: string | null } {
  if (value === null || typeof value !== "object" || safeArrayIsArray(value)) throw new StorageProgrammingError("signed upload options are malformed");
  const contentType = ownValue(value, "contentType");
  const contentLength = ownValue(value, "contentLength");
  const checksumSha256 = ownValue(value, "checksumSha256");
  const cacheControlValue = ownValue(value, "cacheControl");
  const expiresValue = ownValue(value, "expiresIn");
  if (typeof contentType !== "string" || contentType.length < 3 || contentType.length > 255 || !/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+(?:;[ -~]+)?$/iu.test(contentType)) throw new StorageProgrammingError("signed upload content type is malformed");
  if (!safeNumberIsSafeInteger(contentLength) || contentLength < 1 || contentLength > 5 * 1024 * 1024 * 1024) throw new StorageProgrammingError("signed upload content length is malformed");
  if (typeof checksumSha256 !== "string" || !/^[A-Za-z0-9+/]{43}=$/u.test(checksumSha256)) throw new StorageProgrammingError("signed upload checksum is malformed");
  if (cacheControlValue !== undefined && (typeof cacheControlValue !== "string" || cacheControlValue.length === 0 || cacheControlValue.length > 512 || /[\r\n]/u.test(cacheControlValue))) throw new StorageProgrammingError("signed upload cache control is malformed");
  return Object.freeze({
    contentType,
    contentLength,
    checksumSha256,
    cacheControl: cacheControlValue === undefined ? null : cacheControlValue,
    expiresIn: validateExpiresIn(expiresValue === undefined ? 300 : expiresValue),
  });
}

async function parseJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text.length > 65_536) throw new Error("storage response is oversized");
  return text === "" ? null : JSON.parse(text) as unknown;
}

function ownValue(value: unknown, key: string): unknown {
  if (value === null || typeof value !== "object" || safeArrayIsArray(value)) return undefined;
  return Object.getOwnPropertyDescriptor(value, key)?.value;
}

function internalError(): StorageApiError {
  return new StorageApiError("internal_error", 500, "Storage request failed");
}

export function createStorageClient(
  storageUrl: string,
  publishableKey?: string,
  options: StorageClientOptions = {},
): StorageClient {
  const baseUrl = normalizeBaseUrl(storageUrl);
  const apiKey = validatePublishableKey(publishableKey);
  const fetcher = options.fetch ?? globalThis.fetch;
  if (typeof fetcher !== "function") throw new StorageProgrammingError("storage fetch is malformed");
  const accessToken = options.accessToken;
  if (accessToken !== undefined && typeof accessToken !== "function") throw new StorageProgrammingError("storage access token provider is malformed");

  const from = (bucketValue: string): StorageBucketClient => {
    const bucket = validateBucket(bucketValue);

    const createSignedUrl = (pathValue: string, expiresValue: number): Promise<StorageResult<SignedUrlData>> => {
      const path = validatePath(pathValue);
      const expiresIn = validateExpiresIn(expiresValue);
      return (async () => {
        try {
          const token = validateToken(await accessToken?.());
          const headers = new Headers({ "content-type": "application/json" });
          if (apiKey !== undefined) headers.set("apikey", apiKey);
          if (token !== undefined) headers.set("authorization", `Bearer ${token}`);
          const response = await fetcher(
            `${baseUrl}/object/sign/${encodeURIComponent(bucket)}/${encodePath(path)}`,
            {
              method: "POST",
              headers,
              body: JSON.stringify({ expiresIn }),
            },
          );
          const body = await parseJson(response);
          if (!response.ok) {
            const error = ownValue(body, "error");
            const code = ownValue(error, "code");
            const message = ownValue(error, "message");
            return {
              data: null,
              error: new StorageApiError(
                typeof code === "string" ? code : "storage_error",
                response.status,
                typeof message === "string" && message.length <= 2_048 ? message : "Storage request failed",
              ),
            };
          }
          const data = parseSignedUrl(ownValue(body, "data"));
          return data === null ? { data: null, error: internalError() } : { data, error: null };
        } catch (error) {
          if (error instanceof StorageProgrammingError) throw error;
          return { data: null, error: internalError() };
        }
      })();
    };

    const createSignedUploadUrl = (pathValue: string, optionsValue: SignedUploadOptions): Promise<StorageResult<SignedUploadData>> => {
      const path = validatePath(pathValue);
      const upload = validateSignedUploadOptions(optionsValue);
      return (async () => {
        try {
          const token = validateToken(await accessToken?.());
          const headers = new Headers({ "content-type": "application/json" });
          if (apiKey !== undefined) headers.set("apikey", apiKey);
          if (token !== undefined) headers.set("authorization", `Bearer ${token}`);
          const response = await fetcher(`${baseUrl}/object/sign-upload/${encodeURIComponent(bucket)}/${encodePath(path)}`, {
            method: "POST",
            headers,
            body: JSON.stringify({
              cacheControl: upload.cacheControl,
              checksumSha256: upload.checksumSha256,
              contentLength: upload.contentLength,
              contentType: upload.contentType,
              expiresIn: upload.expiresIn,
            }),
          });
          const body = await parseJson(response);
          if (!response.ok) return { data: null, error: new StorageApiError("storage_error", response.status, "Storage request failed") };
          const data = parseSignedUpload(ownValue(body, "data"));
          return data === null ? { data: null, error: internalError() } : { data, error: null };
        } catch (error) {
          if (error instanceof StorageProgrammingError) throw error;
          return { data: null, error: internalError() };
        }
      })();
    };

    const remove = (pathValues: readonly string[]): Promise<StorageResult<null>> => {
      if (!safeArrayIsArray(pathValues) || pathValues.length < 1 || pathValues.length > 100) throw new StorageProgrammingError("storage delete paths are malformed");
      const paths: string[] = [];
      for (let index = 0; index < pathValues.length; index += 1) paths.push(validatePath(pathValues[index]));
      return (async () => {
        try {
          const token = validateToken(await accessToken?.());
          const headers = new Headers({ "content-type": "application/json" });
          if (apiKey !== undefined) headers.set("apikey", apiKey);
          if (token !== undefined) headers.set("authorization", `Bearer ${token}`);
          const response = await fetcher(`${baseUrl}/object/${encodeURIComponent(bucket)}`, {
            method: "DELETE",
            headers,
            body: JSON.stringify({ prefixes: paths }),
          });
          const body = await parseJson(response);
          if (!response.ok) return { data: null, error: new StorageApiError("storage_error", response.status, "Storage request failed") };
          return ownValue(body, "data") === null ? { data: null, error: null } : { data: null, error: internalError() };
        } catch (error) {
          if (error instanceof StorageProgrammingError) throw error;
          return { data: null, error: internalError() };
        }
      })();
    };

    return Object.freeze({ createSignedUrl, createSignedUploadUrl, remove });
  };

  return Object.freeze({ from });
}
