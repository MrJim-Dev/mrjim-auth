import express, { type Express } from "express";
import { Pool } from "pg";
import { toExpressHandler, type ExpressRequest, type ExpressResponse } from "mrjim-auth/express";
import { createPostgresAdapter } from "mrjim-auth/postgres";
import { createAuthServer, PostgresRateLimiter } from "mrjim-auth/server";
import { allowedRedirects, httpUrl, privateJwk, requiredEnv, secretBytes } from "./config.js";
import { authorizationRequest, sampleInvoices } from "./example.js";

const databaseUrl = requiredEnv("DATABASE_URL");
const authBaseUrl = httpUrl("AUTH_BASE_URL");
const siteUrl = httpUrl("AUTH_SITE_URL");
const tokenHashKey = secretBytes("AUTH_TOKEN_HASH_KEY", undefined, 32);
const encryptionKey = secretBytes("AUTH_ENCRYPTION_KEY");
const rateLimitKey = secretBytes("AUTH_RATE_LIMIT_HASH_KEY", undefined, 32);
const keyId = requiredEnv("AUTH_ES256_KEY_ID");
const environment = process.env.AUTH_ENVIRONMENT === "production" ? "production" : "development";

const pool = new Pool({ connectionString: databaseUrl, max: 10 });
const repository = createPostgresAdapter({ pool });
const authServer = createAuthServer({
  environment,
  baseUrl: authBaseUrl,
  siteUrl,
  database: repository,
  signingKeys: {
    issuer: authBaseUrl,
    audience: requiredEnv("AUTH_TOKEN_AUDIENCE"),
    activeKeyId: keyId,
    keys: { [keyId]: privateJwk() },
  },
  secrets: { tokenHashKey, encryptionKey },
  email: {
    async send(message) {
      // Development adapter: replace with project SMTP. Never log message.variables.
      console.info("mail queued", { template: message.template, to: message.to });
    },
  },
  rateLimiter: new PostgresRateLimiter({ pool, hmacKey: rateLimitKey }),
  redirects: { allowed: allowedRedirects() },
  authorization: {
    defaultRoleKeys: ["user" as never],
    protectedRoleKeys: ["admin" as never],
    allowWildcards: false,
  },
  accessTokenTtlSeconds: 900,
  refreshTokenTtlSeconds: 30 * 24 * 60 * 60,
});

const app: Express = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "64kb", strict: true }));
const authHandler = toExpressHandler(authServer);
app.use("/auth/v1", async (request, response) => {
  await authHandler(request as unknown as ExpressRequest, response as unknown as ExpressResponse);
});

app.get("/invoices", async (request, response) => {
  try {
    const subject = await authServer.authorize(
      authorizationRequest(request, authBaseUrl),
      { all: ["invoice.read"] },
    );
    response.setHeader("cache-control", "no-store");
    response.json({ data: { user_id: subject.user_id, invoices: sampleInvoices } });
  } catch {
    response.setHeader("cache-control", "no-store");
    response.status(403).json({ error: { code: "insufficient_permission", message: "Insufficient permission" } });
  }
});

const port = Number.parseInt(process.env.PORT ?? "3000", 10);
if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("PORT is invalid");
const listener = app.listen(port, "127.0.0.1", () => console.log(`Express API listening on http://127.0.0.1:${port}`));

async function shutdown(): Promise<void> {
  listener.close();
  await pool.end();
}

process.once("SIGINT", () => void shutdown());
process.once("SIGTERM", () => void shutdown());

export { app, authServer };
