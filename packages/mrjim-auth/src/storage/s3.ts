import {
  DeleteObjectsCommand,
  GetObjectCommand,
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
}

export interface SignedUploadData {
  readonly signedUrl: string;
  readonly requiredHeaders: Readonly<Record<string, string>>;
}

export interface RemoveObjectsInput {
  readonly bucket: string;
  readonly keys: readonly string[];
}

export interface S3StorageAdapter {
  readonly createSignedReadUrl: (input: SignedReadInput) => Promise<string>;
  readonly createSignedUploadUrl: (input: SignedUploadInput) => Promise<SignedUploadData>;
  readonly remove: (input: RemoveObjectsInput) => Promise<void>;
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
    output[alias] = Object.freeze({
      bucket: mapping.bucket,
      prefix,
      ...(mapping.publicBaseUrl === undefined ? {} : { publicBaseUrl: mapping.publicBaseUrl }),
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
          signableHeaders: new Set(["cache-control", "content-length", "content-type"]),
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
    });
    const signedUrl = await signer(options.client, command, { expiresIn });
    const requiredHeaders = Object.freeze({
      "content-type": contentType,
      "content-length": String(contentLength),
      "x-amz-checksum-sha256": checksumSha256,
      ...(cacheControl === undefined ? {} : { "cache-control": cacheControl }),
    });
    return Object.freeze({ signedUrl, requiredHeaders });
  };

  const remove = async (input: RemoveObjectsInput): Promise<void> => {
    const mapping = resolveBucket(mappings, input.bucket);
    if (!Array.isArray(input.keys) || input.keys.length < 1 || input.keys.length > 1_000) throw new TypeError("storage delete keys are malformed");
    const objects = input.keys.map((key) => ({ Key: resolveKey(mapping, key) }));
    await options.client.send(new DeleteObjectsCommand({
      Bucket: mapping.bucket,
      Delete: { Objects: objects, Quiet: true },
    }));
  };

  return Object.freeze({ createSignedReadUrl, createSignedUploadUrl, remove });
}
