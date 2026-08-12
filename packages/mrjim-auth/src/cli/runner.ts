import { Pool } from "pg";
import { runDoctor, type DoctorEnvironment } from "./commands/doctor.js";
import { runMigrateCommand, type MigrateCommand } from "./commands/migrate.js";
import { runGenerateKeyCommand, type GenerateKeyCommand } from "./commands/keys.js";

/** One line written to CLI stdout or stderr. */
export type CliOutput = (line: string) => void;

class CliUsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CliUsageError";
  }
}

function usageError(message: string): Error {
  return new CliUsageError(`${message}. Usage: mrjim-auth migrate <status|up|verify> | mrjim-auth doctor | mrjim-auth keys generate --kind <publishable|secret> --name <name>`);
}

function safeErrorMessage(error: unknown): string {
  if (error instanceof Error && (error.name === "MigrationError" || error.message.startsWith("schema verification failed:"))) {
    return error.message;
  }
  if (error instanceof Error && error.message.startsWith("DATABASE_URL")) return error.message;
  if (error instanceof Error && error.message.startsWith("MRJIM_AUTH_API_KEY_HASH_KEY")) return error.message;
  if (error instanceof Error && error.name === "CliUsageError") return error.message;
  return "command failed; inspect configuration and database availability";
}

function parseDatabaseUrl(environment: DoctorEnvironment): string {
  const value = environment.DATABASE_URL;
  if (!value) throw new Error("DATABASE_URL is required");
  try {
    const parsed = new URL(value);
    if ((parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:")
      || (parsed.hostname.length === 0 && !parsed.searchParams.has("host"))) {
      throw new Error("invalid database URL");
    }
  } catch {
    throw new Error("DATABASE_URL must be a PostgreSQL URL");
  }
  return value;
}

/** Run the Task 3 CLI without terminating the importing process. */
export async function runCli(
  argv: readonly string[],
  environment: DoctorEnvironment = process.env,
  write: CliOutput = (line) => console.log(line),
  writeError: CliOutput = (line) => console.error(line),
): Promise<number> {
  let pool: Pool | undefined;
  try {
    const [command, subcommand, ...rest] = argv;

    if (command === "keys") {
      if (subcommand !== "generate") throw usageError("expected keys generate");
      let kind: GenerateKeyCommand["kind"] | undefined;
      let name: string | undefined;
      for (let index = 0; index < rest.length; index += 2) {
        const flag = rest[index]; const value = rest[index + 1];
        if (value === undefined) throw usageError("missing option value");
        if (flag === "--kind" && (value === "publishable" || value === "secret") && kind === undefined) kind = value;
        else if (flag === "--name" && name === undefined) name = value;
        else throw usageError("invalid keys generate options");
      }
      if (kind === undefined || name === undefined || name.trim() !== name || name.length < 1 || name.length > 128) throw usageError("--kind and bounded --name are required");
      pool = new Pool({ connectionString: parseDatabaseUrl(environment), max: 4 });
      await runGenerateKeyCommand(pool, { kind, name }, environment, write);
      return 0;
    }

    if (rest.length > 0) throw usageError("unexpected arguments");

    if (command === "doctor") {
      if (subcommand) throw usageError("doctor does not accept a subcommand");
      pool = new Pool({ connectionString: parseDatabaseUrl(environment), max: 4 });
      const report = await runDoctor(pool, environment);
      write(JSON.stringify(report, null, 2));
      return report.ok ? 0 : 1;
    }

    if (command !== "migrate" || (subcommand !== "status" && subcommand !== "up" && subcommand !== "verify")) {
      throw usageError("expected migrate status|up|verify or doctor");
    }

    pool = new Pool({ connectionString: parseDatabaseUrl(environment), max: 4 });
    await runMigrateCommand(pool, subcommand as MigrateCommand, write);
    return 0;
  } catch (error) {
    writeError(`error: ${safeErrorMessage(error)}`);
    return 1;
  } finally {
    await pool?.end().catch(() => undefined);
  }
}

/** Process entrypoint for the packaged `mrjim-auth` binary. */
export async function main(): Promise<void> {
  const exitCode = await runCli(process.argv.slice(2));
  if (exitCode !== 0) process.exitCode = exitCode;
}
