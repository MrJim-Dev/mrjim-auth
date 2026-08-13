# Storage reference

`mrjim-auth` exposes a browser-safe storage namespace and a separate Node-only
S3 adapter. Browser code never receives AWS credentials or imports the AWS SDK.

## Browser client

```ts compile
import { createClient } from "mrjim-auth";

const client = createClient(
  "https://api.example.test/auth/v1",
  "publishable-project-key",
  { storage: { url: "https://api.example.test/storage/v1" } },
);

const result = await client.storage
  .from("private-media")
  .createSignedUrl("users/user-1/avatar.webp", 900);

if (result.error === null) console.log(result.data.signedUrl);
client.auth.dispose();
```

`createSignedUploadUrl` requires the final byte length, MIME type, and base64
SHA-256 checksum. The caller must send every returned `requiredHeaders` entry
unchanged when uploading to the signed URL. `remove` accepts 1 to 100 exact
object keys. Bucket aliases and keys reject traversal and ambiguous paths.

All authorization remains server-side. A locally stored auth session is used
only to attach a bearer token; the storage API must validate that token and
authorize the requested bucket, key, and operation.

## S3 adapter

```ts compile
import { S3Client } from "@aws-sdk/client-s3";
import { createS3StorageAdapter } from "mrjim-auth/storage/s3";

const adapter = createS3StorageAdapter({
  client: new S3Client({ region: "ap-southeast-1" }),
  buckets: {
    "private-media": {
      bucket: "project-production-assets",
      prefix: "private-media/",
    },
  },
});

const signedUrl = await adapter.createSignedReadUrl({
  bucket: "private-media",
  key: "users/user-1/avatar.webp",
  expiresIn: 900,
});

console.log(signedUrl);
```

The adapter uses the AWS SDK v3 default credential chain unless the supplied
`S3Client` is configured otherwise. Prefer workload identity or short-lived
assumed-role credentials. Logical aliases map to physical S3 buckets and fixed
prefixes so applications do not expose provider topology to browser callers.
