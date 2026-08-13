import type { Pool, QueryResultRow } from "pg";
import { queryRows, readSchemaCatalog } from "./internal/catalog.js";
import { readMigrationStatuses } from "./internal/migration-state.js";
import {
  containsForbiddenAuthName,
  REQUIRED_COLUMNS,
  REQUIRED_CONSTRAINTS,
  REQUIRED_FUNCTIONS,
  REQUIRED_INDEXES,
  REQUIRED_TABLES,
  REQUIRED_TRIGGERS,
  columnMatches,
  constraintMatches,
  functionMatches,
  indexMatches,
  triggerMatches,
  type RequiredTable,
} from "./internal/schema-contract.js";

const minimumPostgresVersion = 150000;

interface VersionRow extends QueryResultRow {
  readonly server_version_num: string;
}

interface ExtensionRow extends QueryResultRow {
  readonly extversion: string;
}

/** Read-only result of canonical auth-schema verification. */
export interface SchemaVerification {
  /** True only when every required catalog and migration check passes. */
  readonly ok: boolean;
  /** Stable human-readable failures; no database credentials or secret values. */
  readonly errors: readonly string[];
  /** Base tables found in the auth schema. */
  readonly tables: readonly string[];
  /** Installed pgcrypto version, or null when absent. */
  readonly extensionVersion: string | null;
  /** Numeric PostgreSQL server version, or null when unavailable. */
  readonly postgresVersion: number | null;
}

function hasSameNames(actual: readonly string[], expected: readonly string[]): boolean {
  return actual.length === expected.length && actual.every((value, index) => value === expected[index]);
}

/** Verify tables, typed columns, defaults, indexes, constraints, functions, triggers, extension, and history. */
export async function verifySchema(pool: Pool): Promise<SchemaVerification> {
  const errors: string[] = [];
  const catalog = await readSchemaCatalog(pool);
  const tables = catalog.tables.map((row) => row.table_name);

  if (tables.length === 0) errors.push("auth schema is missing");
  for (const table of REQUIRED_TABLES) {
    if (!tables.includes(table)) errors.push(`required table is missing: auth.${table}`);
  }
  for (const table of tables) {
    if (!REQUIRED_TABLES.includes(table as RequiredTable)) {
      errors.push(`unexpected table in auth schema: auth.${table}`);
    }
  }

  const versionRows = await queryRows<VersionRow>(pool, "SHOW server_version_num");
  const postgresVersionValue = Number(versionRows[0]?.server_version_num);
  const postgresVersion = Number.isFinite(postgresVersionValue) ? postgresVersionValue : null;
  if (postgresVersion === null || postgresVersion < minimumPostgresVersion) {
    errors.push("PostgreSQL 15 or newer is required");
  }

  const extensionRows = await queryRows<ExtensionRow>(
    pool,
    "SELECT extversion FROM pg_extension WHERE extname = 'pgcrypto'",
  );
  const extensionVersion = extensionRows[0]?.extversion ?? null;
  if (!extensionVersion) errors.push("required extension pgcrypto is missing");

  for (const table of REQUIRED_TABLES) {
    const expected = REQUIRED_COLUMNS[table];
    const actual = catalog.columns.filter((row) => row.table_name === table);
    if (!hasSameNames(actual.map((row) => row.column_name), expected.map((row) => row.columnName))) {
      errors.push(`columns do not match for auth.${table}`);
      continue;
    }
    for (const [index, expectedColumn] of expected.entries()) {
      if (!columnMatches(actual[index], expectedColumn)) {
        errors.push(`column contract mismatch: auth.${table}.${expectedColumn.columnName}`);
      }
    }
  }

  for (const expected of REQUIRED_INDEXES) {
    const actual = catalog.indexes.find((row) => row.index_name === expected.indexName);
    if (!indexMatches(actual, expected)) {
      errors.push(`index contract mismatch: auth.${expected.indexName}`);
    }
  }
  const expectedIndexNames = new Set([
    ...REQUIRED_INDEXES.map((index) => index.indexName),
    ...REQUIRED_CONSTRAINTS
      .filter((constraint) => constraint.constraintType === "p" || constraint.constraintType === "u")
      .map((constraint) => constraint.constraintName),
  ]);
  for (const actual of catalog.indexes) {
    if (!expectedIndexNames.has(actual.index_name)) {
      errors.push(`unexpected index in auth schema: ${actual.index_name}`);
    }
  }

  for (const expected of REQUIRED_CONSTRAINTS) {
    const actual = catalog.constraints.find((row) => row.constraint_name === expected.constraintName);
    if (!constraintMatches(actual, expected)) {
      errors.push(`constraint contract mismatch: auth.${expected.constraintName}`);
    }
  }
  const expectedConstraintNames = new Set(REQUIRED_CONSTRAINTS.map((constraint) => constraint.constraintName));
  for (const actual of catalog.constraints) {
    if (!expectedConstraintNames.has(actual.constraint_name)) {
      errors.push(`unexpected constraint in auth schema: ${actual.constraint_name}`);
    }
  }

  for (const expected of REQUIRED_FUNCTIONS) {
    const actual = catalog.functions.find(
      (row) => row.function_name === expected.functionName
        && row.identity_arguments === expected.identityArguments,
    );
    if (!functionMatches(actual, expected)) {
      errors.push(`function contract mismatch: auth.${expected.functionName}(${expected.identityArguments})`);
    }
  }
  const expectedFunctionNames = new Set(REQUIRED_FUNCTIONS.map((func) => `${func.functionName}(${func.identityArguments})`));
  for (const actual of catalog.functions) {
    if (!expectedFunctionNames.has(`${actual.function_name}(${actual.identity_arguments})`)) {
      errors.push(`unexpected function in auth schema: ${actual.function_name}(${actual.identity_arguments})`);
    }
  }

  for (const expected of REQUIRED_TRIGGERS) {
    const actual = catalog.triggers.find((row) => row.trigger_name === expected.triggerName);
    if (!triggerMatches(actual, expected)) {
      errors.push(`trigger contract mismatch: auth.${expected.triggerName}`);
    }
  }
  const expectedTriggerNames = new Set(REQUIRED_TRIGGERS.map((trigger) => trigger.triggerName));
  for (const actual of catalog.triggers) {
    if (!expectedTriggerNames.has(actual.trigger_name)) {
      errors.push(`unexpected trigger in auth schema: ${actual.trigger_name}`);
    }
  }

  for (const object of catalog.objects) {
    if (containsForbiddenAuthName(object.object_name)) {
      errors.push(`forbidden auth ${object.object_type} name exists: ${object.object_name}`);
    }
  }
  for (const type of catalog.types) {
    if (containsForbiddenAuthName(type.type_name)) {
      errors.push(`forbidden auth type name exists: ${type.type_name}`);
    }
  }

  try {
    const statuses = await readMigrationStatuses(pool);
    for (const status of statuses) {
      if (status.state !== "applied") errors.push(`migration is not clean: ${status.version}`);
    }
  } catch {
    errors.push("migration state could not be read");
  }

  return {
    ok: errors.length === 0,
    errors: [...new Set(errors)],
    tables,
    extensionVersion,
    postgresVersion,
  };
}
