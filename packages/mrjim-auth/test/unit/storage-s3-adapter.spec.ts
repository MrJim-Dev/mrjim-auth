import {
  DeleteObjectsCommand,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import { describe, expect, it } from "vitest";
import { createS3StorageAdapter } from "../../src/storage/s3.js";

describe("S3 storage adapter", () => {
  it("maps a logical bucket and prefix into a signed private read", async () => {
    let signedCommand: object | null = null;
    const adapter = createS3StorageAdapter({
      client: {} as S3Client,
      buckets: {
        "courtera-payment-assets": {
          bucket: "courtera-production-assets",
          prefix: "payment/",
        },
      },
      sign: async (_client, command) => {
        signedCommand = command;
        return "https://s3.example.com/signed-read";
      },
    });

    const signedUrl = await adapter.createSignedReadUrl({
      bucket: "courtera-payment-assets",
      key: "bookings/booking-1/proof/receipt.webp",
      expiresIn: 900,
    });

    expect(signedUrl).toBe("https://s3.example.com/signed-read");
    expect(signedCommand).toBeInstanceOf(GetObjectCommand);
    expect((signedCommand as unknown as GetObjectCommand).input).toEqual({
      Bucket: "courtera-production-assets",
      Key: "payment/bookings/booking-1/proof/receipt.webp",
    });
  });

  it("binds upload content controls into the presigned PUT command", async () => {
    let signedCommand: object | null = null;
    const adapter = createS3StorageAdapter({
      client: {} as S3Client,
      buckets: { media: { bucket: "courtera-production-assets", prefix: "media/" } },
      sign: async (_client, command) => {
        signedCommand = command;
        return "https://s3.example.com/signed-upload";
      },
    });

    const result = await adapter.createSignedUploadUrl({
      bucket: "media",
      key: "venues/venue-1/photo.webp",
      expiresIn: 300,
      contentType: "image/webp",
      contentLength: 2048,
      checksumSha256: "qUiQTy8PR5uPgZdpSzAYSw0u0cHNKh7A+4XSmaGSpEc=",
      cacheControl: "public, max-age=31536000, immutable",
      ifNoneMatch: "*",
    });

    expect(result).toEqual({
      signedUrl: "https://s3.example.com/signed-upload",
      requiredHeaders: {
        "cache-control": "public, max-age=31536000, immutable",
        "content-length": "2048",
        "content-type": "image/webp",
        "if-none-match": "*",
        "x-amz-checksum-sha256": "qUiQTy8PR5uPgZdpSzAYSw0u0cHNKh7A+4XSmaGSpEc=",
      },
    });
    expect(signedCommand).toBeInstanceOf(PutObjectCommand);
    expect((signedCommand as unknown as PutObjectCommand).input).toEqual({
      Bucket: "courtera-production-assets",
      Key: "media/venues/venue-1/photo.webp",
      CacheControl: "public, max-age=31536000, immutable",
      ChecksumSHA256: "qUiQTy8PR5uPgZdpSzAYSw0u0cHNKh7A+4XSmaGSpEc=",
      ContentLength: 2048,
      ContentType: "image/webp",
      IfNoneMatch: "*",
    });
  });

  it("signs checksum and upload control headers in the default presigner", async () => {
    const adapter = createS3StorageAdapter({
      client: new S3Client({
        region: "ap-southeast-1",
        credentials: { accessKeyId: "AKIAEXAMPLE", secretAccessKey: "secret" },
      }),
      buckets: { media: { bucket: "courtera-production-assets" } },
    });

    const result = await adapter.createSignedUploadUrl({
      bucket: "media",
      key: "health-check.txt",
      expiresIn: 300,
      contentType: "text/plain",
      contentLength: 5,
      checksumSha256: "qUiQTy8PR5uPgZdpSzAYSw0u0cHNKh7A+4XSmaGSpEc=",
      cacheControl: "no-store",
    });

    const signedHeaders = new URL(result.signedUrl).searchParams.get("X-Amz-SignedHeaders") ?? "";
    expect(signedHeaders.split(";")).toEqual([
      "cache-control",
      "content-length",
      "content-type",
      "host",
      "x-amz-checksum-sha256",
    ]);
  });

  it("deletes only resolved keys from one configured physical bucket", async () => {
    let sentCommand: object | null = null;
    const client = {
      send: async (command: object) => {
        sentCommand = command;
        return {};
      },
    } as unknown as S3Client;
    const adapter = createS3StorageAdapter({
      client,
      buckets: { media: { bucket: "courtera-production-assets", prefix: "media/" } },
    });

    await adapter.remove({ bucket: "media", keys: ["one.webp", "nested/two.webp"] });

    expect(sentCommand).toBeInstanceOf(DeleteObjectsCommand);
    expect((sentCommand as unknown as DeleteObjectsCommand).input).toEqual({
      Bucket: "courtera-production-assets",
      Delete: {
        Objects: [{ Key: "media/one.webp" }, { Key: "media/nested/two.webp" }],
        Quiet: true,
      },
    });
  });

  it("uploads and downloads resolved objects without buffering unknown streams", async () => {
    const commands: object[] = [];
    const client = {
      send: async (command: object) => {
        commands.push(command);
        if (command instanceof GetObjectCommand) {
          return {
            Body: {
              transformToByteArray: async () => new Uint8Array([1, 2, 3]),
            },
            CacheControl: "private, max-age=60",
            ContentLength: 3,
            ContentType: "image/webp",
          };
        }
        return {};
      },
    } as unknown as S3Client;
    const adapter = createS3StorageAdapter({
      client,
      buckets: { media: { bucket: "courtera-production-assets", prefix: "media/" } },
    });

    await adapter.upload({
      bucket: "media",
      key: "venues/venue-1/photo.webp",
      body: new Uint8Array([1, 2, 3]),
      contentLength: 3,
      contentType: "image/webp",
      cacheControl: "private, max-age=60",
      ifNoneMatch: "*",
    });
    const downloaded = await adapter.download({
      bucket: "media",
      key: "venues/venue-1/photo.webp",
      maxBytes: 4,
    });

    expect(commands[0]).toBeInstanceOf(PutObjectCommand);
    expect((commands[0] as PutObjectCommand).input).toMatchObject({
      Bucket: "courtera-production-assets",
      Key: "media/venues/venue-1/photo.webp",
      ContentLength: 3,
      ContentType: "image/webp",
      CacheControl: "private, max-age=60",
      IfNoneMatch: "*",
    });
    expect(downloaded).toEqual({
      bytes: new Uint8Array([1, 2, 3]),
      cacheControl: "private, max-age=60",
      contentLength: 3,
      contentType: "image/webp",
    });
    expect((commands[1] as GetObjectCommand).input.Range).toBe("bytes=0-4");
  });

  it("checks existence and exposes public URLs only for configured mappings", async () => {
    let sentCommand: object | null = null;
    const client = {
      send: async (command: object) => {
        sentCommand = command;
        return {};
      },
    } as unknown as S3Client;
    const adapter = createS3StorageAdapter({
      client,
      buckets: {
        avatars: {
          bucket: "courtera-production-assets",
          prefix: "avatars/",
          publicBaseUrl: "https://media.courtera.test/avatars",
        },
        private: { bucket: "courtera-production-assets", prefix: "private/" },
      },
    });

    await expect(adapter.exists({ bucket: "avatars", key: "users/user-1/a.webp" })).resolves.toBe(true);
    expect(sentCommand).toBeInstanceOf(HeadObjectCommand);
    expect(adapter.getPublicUrl({ bucket: "avatars", key: "users/user-1/a.webp" })).toBe(
      "https://media.courtera.test/avatars/users/user-1/a.webp",
    );
    expect(() => adapter.getPublicUrl({ bucket: "private", key: "receipt.webp" })).toThrow(
      "storage bucket is not public",
    );
  });
});
