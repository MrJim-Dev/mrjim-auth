import { URL } from "node:url";
import type { Pool } from "pg";
import { verifySchema } from "../../postgres/migrate.js";

const minimumKeyBytes = 32;

export interface DoctorEnvironment {
  readonly [key: string]: string | undefined;
}

export interface DoctorCheck {
  readonly name: string;
  readonly ok: boolean;
}

export interface DoctorReport {
  readonly ok: boolean;
  readonly checks: readonly DoctorCheck[];
  readonly errors: readonly string[];
}

function isHttpUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return (parsed.protocol === "https:" || parsed.protocol === "http:") && parsed.hostname.length > 0;
  } catch {
    return false;
  }
}

function isDatabaseUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return (parsed.protocol === "postgres:" || parsed.protocol === "postgresql:")
      && (parsed.hostname.length > 0 || parsed.searchParams.has("host"));
  } catch {
    return false;
  }
}

function isProduction(environment: DoctorEnvironment): boolean {
  return (environment.AUTH_ENVIRONMENT ?? "production").toLowerCase() === "production";
}

/** Validate deployment configuration and the installed database without changing database state. */
export async function runDoctor(
  pool: Pool,
  environment: DoctorEnvironment,
): Promise<DoctorReport> {
  const errors: string[] = [];
  const checks: DoctorCheck[] = [];
  const addCheck = (name: string, ok: boolean, message: string): void => {
    checks.push({ name, ok });
    if (!ok) errors.push(message);
  };

  const databaseUrl = environment.DATABASE_URL;
  addCheck(
    "database_url",
    typeof databaseUrl === "string" && isDatabaseUrl(databaseUrl),
    "DATABASE_URL must be a PostgreSQL URL",
  );

  for (const [name, label] of [
    ["AUTH_TOKEN_HASH_KEY", "token hash key"],
    ["AUTH_ENCRYPTION_KEY", "encryption key"],
  ] as const) {
    const value = environment[name];
    addCheck(
      name.toLowerCase(),
      typeof value === "string" && Buffer.byteLength(value, "utf8") >= minimumKeyBytes,
      `${label} must contain at least ${minimumKeyBytes} bytes`,
    );
  }

  const production = isProduction(environment);
  for (const [name, label] of [
    ["AUTH_BASE_URL", "AUTH_BASE_URL"],
    ["AUTH_SITE_URL", "AUTH_SITE_URL"],
  ] as const) {
    const value = environment[name];
    const valid = typeof value === "string"
      && isHttpUrl(value)
      && (!production || value.startsWith("https://"));
    addCheck(name.toLowerCase(), valid, `${label} must be an HTTPS URL in production`);
  }

  const redirects = (environment.AUTH_ALLOWED_REDIRECTS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  addCheck(
    "allowed_redirects",
    redirects.every((redirect) => isHttpUrl(redirect) && (!production || redirect.startsWith("https://"))),
    "AUTH_ALLOWED_REDIRECTS must contain only valid HTTPS URLs in production",
  );

  try {
    const verification = await verifySchema(pool);
    addCheck("postgres_version", verification.postgresVersion !== null && verification.postgresVersion >= 150000, "PostgreSQL 15 or newer is required");
    addCheck("pgcrypto", verification.extensionVersion !== null, "pgcrypto is not installed");
    addCheck("migration_state", verification.ok, verification.errors.length ? verification.errors.join("; ") : "migration state is not verified");
  } catch {
    addCheck("database", false, "database health checks could not be completed");
  }

  return { ok: errors.length === 0, checks, errors };
}
