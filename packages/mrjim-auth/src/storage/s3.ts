import {
  DeleteObjectsCommand,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  type S3Client,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const MAX_EXPIRES_IN = 604_800;
const MAX_OBJECT_KEY = 1_024;
const MAX_SINGLE_UPLOAD_BYTES = 5 * 1024 * 1024 * 1024;

export interface StorageBucketMapping {
  readonly bucket: string;
  readonly prefix?: string;
  readonly publicBaseUrl?: string;
}

export interface S3StorageAdapterOptions {
  readonly client: S3Client;
  readonly buckets: Readonly<Record<string, StorageBucketMapping>>;
  readonly sign?: ((client: S3Client, command: object, options: { readonly expiresIn: number }) => Promise<string>) | undefined;
}

export interface SignedReadInput {
  readonly bucket: string;
  readonly key: string;
  readonly expiresIn: number;
}

export interface SignedUploadInput extends SignedReadInput {
  readonly contentType: string;
  readonly contentLength: number;
  readonly checksumSha256: string;
  readonly cacheControl?: string;
  readonly ifNoneMatch?: "*";
}

export interface SignedUploadData {
  readonly signedUrl: string;
  readonly requiredHeaders: Readonly<Record<string, string>>;
}

export interface RemoveObjectsInput {
  readonly bucket: string;
  readonly keys: readonly string[];
}

export interface ObjectInput {
  readonly bucket: string;
  readonly key: string;
}

export interface UploadObjectInput extends ObjectInput {
  readonly body: Uint8Array;
  readonly contentType: string;
  readonly contentLength: number;
  readonly cacheControl?: string;
  readonly ifNoneMatch?: "*";
}

export interface DownloadObjectInput extends ObjectInput {
  readonly maxBytes: number;
}

export interface DownloadObjectData {
  readonly bytes: Uint8Array;
  readonly contentType?: string;
  readonly contentLength: number;
  readonly cacheControl?: string;
}

export interface RemoveObjectsData {
  readonly deleted: readonly string[];
  readonly errors: readonly { readonly key: string; readonly code: string; readonly message: string }[];
}

export interface S3StorageAdapter {
  readonly createSignedReadUrl: (input: SignedReadInput) => Promise<string>;
  readonly createSignedUploadUrl: (input: SignedUploadInput) => Promise<SignedUploadData>;
  readonly download: (input: DownloadObjectInput) => Promise<DownloadObjectData>;
  readonly exists: (input: ObjectInput) => Promise<boolean>;
  readonly getPublicUrl: (input: ObjectInput) => string;
  readonly remove: (input: RemoveObjectsInput) => Promise<RemoveObjectsData>;
  readonly upload: (input: UploadObjectInput) => Promise<void>;
}

interface ResolvedBucket {
  readonly bucket: string;
  readonly prefix: string;
  readonly publicBaseUrl?: string;
}

function validBucketName(value: string): boolean {
  return value.length >= 3
    && value.length <= 63
    && /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/u.test(value)
    && !value.includes("..");
}

function validateObjectKey(value: unknown): string {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > MAX_OBJECT_KEY
    || value.startsWith("/")
    || value.endsWith("/")
    || value.includes("\\")
    || /[\u0000-\u001f\u007f]/u.test(value)
  ) throw new TypeError("storage object key is malformed");
  const segments = value.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
    throw new TypeError("storage object key is malformed");
  }
  return value;
}

function validateExpiresIn(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > MAX_EXPIRES_IN) {
    throw new TypeError("storage URL lifetime is malformed");
  }
  return value as number;
}

function validateMappings(value: S3StorageAdapterOptions["buckets"]): Readonly<Record<string, ResolvedBucket>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError("storage bucket mappings are malformed");
  const output: Record<string, ResolvedBucket> = Object.create(null) as Record<string, ResolvedBucket>;
  for (const [alias, mapping] of Object.entries(value)) {
    if (!validBucketName(alias) || mapping === null || typeof mapping !== "object" || !validBucketName(mapping.bucket)) {
      throw new TypeError("storage bucket mapping is malformed");
    }
    let prefix = mapping.prefix ?? "";
    if (prefix !== "") {
      prefix = validateObjectKey(prefix.replace(/\/+$/u, "")) + "/";
    }
    let publicBaseUrl: string | undefined;
    if (mapping.publicBaseUrl !== undefined) {
      const parsed = new URL(mapping.publicBaseUrl);
      if (
        (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
        parsed.username !== "" || parsed.password !== "" ||
        parsed.search !== "" || parsed.hash !== ""
      ) throw new TypeError("storage public base URL is malformed");
      publicBaseUrl = parsed.toString().replace(/\/+$/u, "");
    }
    output[alias] = Object.freeze({
      bucket: mapping.bucket,
      prefix,
      ...(publicBaseUrl === undefined ? {} : { publicBaseUrl }),
    });
  }
  return Object.freeze(output);
}

function resolveBucket(mappings: Readonly<Record<string, ResolvedBucket>>, alias: string): ResolvedBucket {
  const mapping = Object.getOwnPropertyDescriptor(mappings, alias)?.value as ResolvedBucket | undefined;
  if (mapping === undefined) throw new TypeError("storage bucket is not configured");
  return mapping;
}

function resolveKey(mapping: ResolvedBucket, key: string): string {
  return `${mapping.prefix}${validateObjectKey(key)}`;
}

function validateContentType(value: unknown): string {
  if (typeof value !== "string" || value.length < 3 || value.length > 255 || !/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+(?:;[ -~]+)?$/iu.test(value)) {
    throw new TypeError("storage content type is malformed");
  }
  return value;
}

function validateContentLength(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > MAX_SINGLE_UPLOAD_BYTES) {
    throw new TypeError("storage content length is malformed");
  }
  return value as number;
}

function validateChecksum(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]{43}=$/u.test(value)) throw new TypeError("storage checksum is malformed");
  return value;
}

function validateCacheControl(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0 || value.length > 512 || /[\r\n]/u.test(value)) throw new TypeError("storage cache control is malformed");
  return value;
}

export function createS3StorageAdapter(options: S3StorageAdapterOptions): S3StorageAdapter {
  if (options === null || typeof options !== "object" || options.client === null || typeof options.client !== "object") {
    throw new TypeError("S3 storage adapter options are malformed");
  }
  const mappings = validateMappings(options.buckets);
  const signer = options.sign ?? (async (client, command, signOptions) => {
    const uploadSigningOptions = command instanceof PutObjectCommand
      ? {
          ...signOptions,
          signableHeaders: new Set(["cache-control", "content-length", "content-type", "if-none-match"]),
          unhoistableHeaders: new Set(["x-amz-checksum-sha256"]),
        }
      : signOptions;
    return await getSignedUrl(
      client,
      command as GetObjectCommand | PutObjectCommand,
      uploadSigningOptions,
    );
  });

  const createSignedReadUrl = async (input: SignedReadInput): Promise<string> => {
    const mapping = resolveBucket(mappings, input.bucket);
    const expiresIn = validateExpiresIn(input.expiresIn);
    const command = new GetObjectCommand({ Bucket: mapping.bucket, Key: resolveKey(mapping, input.key) });
    return await signer(options.client, command, { expiresIn });
  };

  const createSignedUploadUrl = async (input: SignedUploadInput): Promise<SignedUploadData> => {
    const mapping = resolveBucket(mappings, input.bucket);
    const expiresIn = validateExpiresIn(input.expiresIn);
    const contentType = validateContentType(input.contentType);
    const contentLength = validateContentLength(input.contentLength);
    const checksumSha256 = validateChecksum(input.checksumSha256);
    const cacheControl = validateCacheControl(input.cacheControl);
    const command = new PutObjectCommand({
      Bucket: mapping.bucket,
      Key: resolveKey(mapping, input.key),
      ContentType: contentType,
      ContentLength: contentLength,
      ChecksumSHA256: checksumSha256,
      ...(cacheControl === undefined ? {} : { CacheControl: cacheControl }),
      ...(input.ifNoneMatch === undefined ? {} : { IfNoneMatch: input.ifNoneMatch }),
    });
    const signedUrl = await signer(options.client, command, { expiresIn });
    const requiredHeaders = Object.freeze({
      "content-type": contentType,
      "content-length": String(contentLength),
      "x-amz-checksum-sha256": checksumSha256,
      ...(cacheControl === undefined ? {} : { "cache-control": cacheControl }),
      ...(input.ifNoneMatch === undefined ? {} : { "if-none-match": input.ifNoneMatch }),
    });
    return Object.freeze({ signedUrl, requiredHeaders });
  };

  const upload = async (input: UploadObjectInput): Promise<void> => {
    const mapping = resolveBucket(mappings, input.bucket);
    const contentType = validateContentType(input.contentType);
    const contentLength = validateContentLength(input.contentLength);
    const cacheControl = validateCacheControl(input.cacheControl);
    if (!(input.body instanceof Uint8Array) || input.body.byteLength !== contentLength) {
      throw new TypeError("storage upload body is malformed");
    }
    await options.client.send(new PutObjectCommand({
      Bucket: mapping.bucket,
      Key: resolveKey(mapping, input.key),
      Body: input.body,
      ContentLength: contentLength,
      ContentType: contentType,
      ...(cacheControl === undefined ? {} : { CacheControl: cacheControl }),
      ...(input.ifNoneMatch === undefined ? {} : { IfNoneMatch: input.ifNoneMatch }),
    }));
  };

  const download = async (input: DownloadObjectInput): Promise<DownloadObjectData> => {
    const mapping = resolveBucket(mappings, input.bucket);
    const maxBytes = validateContentLength(input.maxBytes);
    const response = await options.client.send(new GetObjectCommand({
      Bucket: mapping.bucket,
      Key: resolveKey(mapping, input.key),
      Range: `bytes=0-${maxBytes}`,
    }));
    if (typeof response.ContentLength === "number" && response.ContentLength > maxBytes) {
      throw new RangeError("storage object exceeds download limit");
    }
    const body = response.Body;
    if (!body || typeof body.transformToByteArray !== "function") {
      throw new TypeError("storage download body is unavailable");
    }
    const bytes = await body.transformToByteArray();
    if (bytes.byteLength > maxBytes) throw new RangeError("storage object exceeds download limit");
    return Object.freeze({
      bytes,
      contentLength: bytes.byteLength,
      ...(response.ContentType === undefined ? {} : { contentType: response.ContentType }),
      ...(response.CacheControl === undefined ? {} : { cacheControl: response.CacheControl }),
    });
  };

  const exists = async (input: ObjectInput): Promise<boolean> => {
    const mapping = resolveBucket(mappings, input.bucket);
    try {
      await options.client.send(new HeadObjectCommand({
        Bucket: mapping.bucket,
        Key: resolveKey(mapping, input.key),
      }));
      return true;
    } catch (error) {
      const candidate = error as { readonly name?: unknown; readonly $metadata?: { readonly httpStatusCode?: unknown } };
      if (candidate?.name === "NotFound" || candidate?.name === "NoSuchKey" || candidate?.$metadata?.httpStatusCode === 404) return false;
      throw error;
    }
  };

  const getPublicUrl = (input: ObjectInput): string => {
    const mapping = resolveBucket(mappings, input.bucket);
    if (mapping.publicBaseUrl === undefined) throw new TypeError("storage bucket is not public");
    const base = mapping.publicBaseUrl.replace(/\/+$/u, "");
    const encodedKey = validateObjectKey(input.key).split("/").map(encodeURIComponent).join("/");
    return `${base}/${encodedKey}`;
  };

  const remove = async (input: RemoveObjectsInput): Promise<RemoveObjectsData> => {
    const mapping = resolveBucket(mappings, input.bucket);
    if (!Array.isArray(input.keys) || input.keys.length < 1 || input.keys.length > 1_000) throw new TypeError("storage delete keys are malformed");
    const objects = input.keys.map((key) => ({ Key: resolveKey(mapping, key) }));
    const response = await options.client.send(new DeleteObjectsCommand({
      Bucket: mapping.bucket,
      Delete: { Objects: objects, Quiet: true },
    }));
    const errors = (response.Errors ?? []).map((error) => Object.freeze({
      key: typeof error.Key === "string" && error.Key.startsWith(mapping.prefix)
        ? error.Key.slice(mapping.prefix.length)
        : "",
      code: error.Code ?? "Unknown",
      message: error.Message ?? "S3 object deletion failed",
    }));
    const failed = new Set(errors.map((error) => error.key));
    return Object.freeze({
      deleted: Object.freeze(input.keys.filter((key) => !failed.has(key))),
      errors: Object.freeze(errors),
    });
  };

  return Object.freeze({ createSignedReadUrl, createSignedUploadUrl, download, exists, getPublicUrl, remove, upload });
}
