import { describe, expect, it, vi } from "vitest";
import { createClient } from "../../src/index.js";
import { createStorageClient } from "../../src/storage/client.js";
import { StorageProgrammingError } from "../../src/storage/errors.js";

const STORAGE_URL = "https://project.example.com/storage/v1";
const ACCESS_TOKEN = "access-token-sentinel";

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify({ data, error: null }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("browser-safe storage client", () => {
  it("composes an immutable storage namespace into the project client", () => {
    const client = createClient("https://project.example.com/auth/v1", "publishable-key", {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
        detectSessionInUrl: false,
        skipAutoInitialize: true,
      },
      global: { fetch: vi.fn() as unknown as typeof fetch },
    });

    expect(Object.keys(client)).toEqual(["auth", "storage"]);
    expect(Object.isFrozen(client.storage)).toBe(true);
    expect(typeof client.storage.from).toBe("function");
    client.auth.dispose();
  });

  it("requests a signed object URL with the authenticated project boundary", async () => {
    const calls: Array<readonly [RequestInfo | URL, RequestInit | undefined]> = [];
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push([input, init]);
      return jsonResponse({
        signedUrl: "https://cdn.example.com/private/object?signature=opaque",
      });
    }) as typeof fetch;
    const client = createStorageClient(STORAGE_URL, "publishable-key", {
      accessToken: async () => ACCESS_TOKEN,
      fetch: fetcher,
    });

    const result = await client
      .from("courtera-payment-assets")
      .createSignedUrl("bookings/booking-1/proof/receipt.webp", 900);

    expect(result).toEqual({
      data: { signedUrl: "https://cdn.example.com/private/object?signature=opaque" },
      error: null,
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
    const [input, init] = calls[0]!;
    const request = new Request(input, init);
    expect(request.url).toBe(
      "https://project.example.com/storage/v1/object/sign/courtera-payment-assets/bookings/booking-1/proof/receipt.webp",
    );
    expect(request.method).toBe("POST");
    expect(request.headers.get("authorization")).toBe(`Bearer ${ACCESS_TOKEN}`);
    expect(request.headers.get("apikey")).toBe("publishable-key");
    expect(request.headers.get("content-type")).toBe("application/json");
    expect(await request.json()).toEqual({ expiresIn: 900 });
  });

  it("rejects ambiguous buckets and object keys before token or network access", () => {
    const accessToken = vi.fn(async () => ACCESS_TOKEN);
    const fetcher = vi.fn();
    const client = createStorageClient(STORAGE_URL, "publishable-key", {
      accessToken,
      fetch: fetcher as unknown as typeof fetch,
    });

    expect(() => client.from("../payment-assets")).toThrow(StorageProgrammingError);
    expect(() => client.from("payment-assets").createSignedUrl("../secret", 900)).toThrow(StorageProgrammingError);
    expect(accessToken).not.toHaveBeenCalled();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("requests a constrained signed upload and returns required S3 headers", async () => {
    const calls: Array<readonly [RequestInfo | URL, RequestInit | undefined]> = [];
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push([input, init]);
      return jsonResponse({
        signedUrl: "https://s3.example.com/signed-upload",
        requiredHeaders: {
          "content-type": "image/webp",
          "content-length": "2048",
          "x-amz-checksum-sha256": "qUiQTy8PR5uPgZdpSzAYSw0u0cHNKh7A+4XSmaGSpEc=",
        },
      });
    }) as typeof fetch;
    const client = createStorageClient(STORAGE_URL, "publishable-key", {
      accessToken: async () => ACCESS_TOKEN,
      fetch: fetcher,
    });

    const result = await client.from("courtera-venue-media").createSignedUploadUrl(
      "venues/venue-1/photo.webp",
      {
        contentType: "image/webp",
        contentLength: 2048,
        checksumSha256: "qUiQTy8PR5uPgZdpSzAYSw0u0cHNKh7A+4XSmaGSpEc=",
      },
    );

    expect(result.error).toBeNull();
    expect(result.data).toEqual({
      signedUrl: "https://s3.example.com/signed-upload",
      requiredHeaders: {
        "content-type": "image/webp",
        "content-length": "2048",
        "x-amz-checksum-sha256": "qUiQTy8PR5uPgZdpSzAYSw0u0cHNKh7A+4XSmaGSpEc=",
      },
    });
    const [input, init] = calls[0]!;
    const request = new Request(input, init);
    expect(request.url).toBe("https://project.example.com/storage/v1/object/sign-upload/courtera-venue-media/venues/venue-1/photo.webp");
    expect(await request.json()).toEqual({
      cacheControl: null,
      checksumSha256: "qUiQTy8PR5uPgZdpSzAYSw0u0cHNKh7A+4XSmaGSpEc=",
      contentLength: 2048,
      contentType: "image/webp",
      expiresIn: 300,
    });
  });

  it("requests one bounded bucket-scoped object deletion", async () => {
    const calls: Array<readonly [RequestInfo | URL, RequestInit | undefined]> = [];
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push([input, init]);
      return jsonResponse(null);
    }) as typeof fetch;
    const client = createStorageClient(STORAGE_URL, "publishable-key", {
      accessToken: async () => ACCESS_TOKEN,
      fetch: fetcher,
    });

    const result = await client.from("courtera-venue-media").remove([
      "venues/venue-1/old.webp",
      "venues/venue-1/other.webp",
    ]);

    expect(result).toEqual({ data: null, error: null });
    const [input, init] = calls[0]!;
    const request = new Request(input, init);
    expect(request.url).toBe("https://project.example.com/storage/v1/object/courtera-venue-media");
    expect(request.method).toBe("DELETE");
    expect(await request.json()).toEqual({
      prefixes: ["venues/venue-1/old.webp", "venues/venue-1/other.webp"],
    });
  });
});
