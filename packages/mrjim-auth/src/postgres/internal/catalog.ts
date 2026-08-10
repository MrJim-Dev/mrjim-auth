import type { Pool, PoolClient, QueryResultRow } from "pg";

/** A checked-out pg executor used by read-only catalog queries. */
export type QueryExecutor = Pool | PoolClient;

/** Typed catalog row for an auth table. */
export interface TableCatalogRow extends QueryResultRow {
  readonly table_name: string;
}

/** Typed catalog row for an auth column. */
export interface ColumnCatalogRow extends QueryResultRow {
  readonly table_name: string;
  readonly column_name: string;
  readonly ordinal_position: number;
  readonly data_type: string;
  readonly udt_name: string;
  readonly is_nullable: "YES" | "NO";
  readonly column_default: string | null;
}

/** Typed catalog row for an auth index. */
export interface IndexCatalogRow extends QueryResultRow {
  readonly index_name: string;
  readonly is_unique: boolean;
  readonly is_primary: boolean;
  readonly index_definition: string;
  readonly predicate: string | null;
  readonly index_valid: boolean;
  readonly index_ready: boolean;
}

/** Typed catalog row for an auth constraint. */
export interface ConstraintCatalogRow extends QueryResultRow {
  readonly constraint_name: string;
  readonly constraint_type: string;
  readonly definition: string;
  readonly is_validated: boolean;
  readonly is_deferrable: boolean;
  readonly initially_deferred: boolean;
  readonly delete_action: string | null;
  readonly table_name: string;
  readonly referenced_table_name: string | null;
  readonly local_columns: readonly (string | null)[];
  readonly referenced_columns: readonly (string | null)[];
}

/** Typed catalog row for an auth function. */
export interface FunctionCatalogRow extends QueryResultRow {
  readonly function_name: string;
  readonly identity_arguments: string;
  readonly return_type: string;
  readonly language_name: string;
  readonly definition: string;
  readonly prosrc: string;
  readonly volatility: "i" | "s" | "v";
  readonly parallel_safety: "s" | "r" | "u";
  readonly security_definer: boolean;
  readonly leakproof: boolean;
  readonly is_strict: boolean;
  readonly config: readonly (string | null)[] | null;
}

/** Typed catalog row for an auth-schema type. */
export interface TypeCatalogRow extends QueryResultRow {
  readonly type_name: string;
  readonly type_kind: string;
}

/** Typed catalog row for a non-internal auth trigger. */
export interface TriggerCatalogRow extends QueryResultRow {
  readonly trigger_name: string;
  readonly table_name: string;
  readonly function_name: string;
  readonly enabled: string;
  readonly trigger_type: number;
  readonly definition: string;
}

/** Typed auth-schema object name used by the forbidden-name guard. */
export interface AuthObjectNameRow extends QueryResultRow {
  readonly object_type: string;
  readonly object_name: string;
}

/** Typed row recorded by auth.schema_migrations. */
export interface AppliedMigrationCatalogRow extends QueryResultRow {
  readonly version: string;
  readonly migration_order: number;
  readonly checksum: string;
  readonly applied_at: Date;
  readonly package_version: string;
}

/** Typed scalar row for existence checks. */
interface ExistsCatalogRow extends QueryResultRow {
  readonly exists: boolean;
}

/** Execute a catalog query and return rows without untyped catalog casts. */
export async function queryRows<Row extends QueryResultRow>(
  executor: QueryExecutor,
  text: string,
  values: readonly unknown[] = [],
): Promise<readonly Row[]> {
  const result = await executor.query<Row>(text, [...values]);
  return result.rows;
}

/** Read whether the migration bookkeeping table already exists. */
export async function migrationTableExists(executor: QueryExecutor): Promise<boolean> {
  const rows = await queryRows<ExistsCatalogRow>(
    executor,
    "SELECT to_regclass('auth.schema_migrations') IS NOT NULL AS exists",
  );
  return rows[0]?.exists === true;
}

/** Read applied migration rows without changing database state. */
export async function readAppliedMigrationRows(
  executor: QueryExecutor,
): Promise<readonly AppliedMigrationCatalogRow[]> {
  if (!(await migrationTableExists(executor))) return [];
  return queryRows<AppliedMigrationCatalogRow>(
    executor,
    `SELECT version, migration_order, checksum, applied_at, package_version
       FROM auth.schema_migrations
      ORDER BY migration_order, version`,
  );
}

/** Read the complete catalog needed to verify the canonical auth schema. */
export async function readSchemaCatalog(executor: QueryExecutor): Promise<{
  readonly tables: readonly TableCatalogRow[];
  readonly columns: readonly ColumnCatalogRow[];
  readonly indexes: readonly IndexCatalogRow[];
  readonly constraints: readonly ConstraintCatalogRow[];
  readonly functions: readonly FunctionCatalogRow[];
  readonly types: readonly TypeCatalogRow[];
  readonly triggers: readonly TriggerCatalogRow[];
  readonly objects: readonly AuthObjectNameRow[];
}> {
  const tables = await queryRows<TableCatalogRow>(
    executor,
    `SELECT c.relname AS table_name
       FROM pg_class AS c
       JOIN pg_namespace AS n ON n.oid = c.relnamespace
      WHERE n.nspname = 'auth' AND c.relkind IN ('r', 'p')
      ORDER BY c.relname`,
  );
  const columns = await queryRows<ColumnCatalogRow>(
    executor,
    `SELECT table_name, column_name, ordinal_position, data_type, udt_name,
            is_nullable, column_default
       FROM information_schema.columns
      WHERE table_schema = 'auth'
      ORDER BY table_name, ordinal_position`,
  );
  const indexes = await queryRows<IndexCatalogRow>(
    executor,
    `SELECT index_class.relname AS index_name,
            index_row.indisunique AS is_unique,
            index_row.indisprimary AS is_primary,
            pg_get_indexdef(index_row.indexrelid) AS index_definition,
            pg_get_expr(index_row.indpred, index_row.indrelid) AS predicate,
            index_row.indisvalid AS index_valid,
            index_row.indisready AS index_ready
       FROM pg_index AS index_row
       JOIN pg_class AS index_class ON index_class.oid = index_row.indexrelid
       JOIN pg_namespace AS namespace_row ON namespace_row.oid = index_class.relnamespace
      WHERE namespace_row.nspname = 'auth'
      ORDER BY index_class.relname`,
  );
  const constraints = await queryRows<ConstraintCatalogRow>(
    executor,
    `SELECT constraint_row.conname AS constraint_name,
            constraint_row.contype AS constraint_type,
            pg_get_constraintdef(constraint_row.oid, true) AS definition,
            constraint_row.convalidated AS is_validated,
            constraint_row.condeferrable AS is_deferrable,
            constraint_row.condeferred AS initially_deferred,
            CASE constraint_row.confdeltype
              WHEN 'a' THEN 'RESTRICT'
              WHEN 'r' THEN 'RESTRICT'
              WHEN 'c' THEN 'CASCADE'
              WHEN 'n' THEN 'SET NULL'
              WHEN 'd' THEN 'SET DEFAULT'
              ELSE NULL
            END AS delete_action,
            local_class.relname AS table_name,
            referenced_class.relname AS referenced_table_name,
            COALESCE(array_agg(local_attribute.attname ORDER BY local_key.ord)
              FILTER (WHERE local_key.attnum IS NOT NULL), ARRAY[]::name[])::text[] AS local_columns,
            COALESCE(array_agg(referenced_attribute.attname ORDER BY referenced_key.ord)
              FILTER (WHERE referenced_key.attnum IS NOT NULL), ARRAY[]::name[])::text[] AS referenced_columns
       FROM pg_constraint AS constraint_row
       JOIN pg_namespace AS namespace_row ON namespace_row.oid = constraint_row.connamespace
       LEFT JOIN pg_class AS local_class ON local_class.oid = constraint_row.conrelid
       LEFT JOIN pg_class AS referenced_class ON referenced_class.oid = constraint_row.confrelid
       LEFT JOIN LATERAL unnest(constraint_row.conkey) WITH ORDINALITY AS local_key(attnum, ord)
         ON true
       LEFT JOIN pg_attribute AS local_attribute
         ON local_attribute.attrelid = constraint_row.conrelid
        AND local_attribute.attnum = local_key.attnum
       LEFT JOIN LATERAL unnest(constraint_row.confkey) WITH ORDINALITY AS referenced_key(attnum, ord)
         ON true
       LEFT JOIN pg_attribute AS referenced_attribute
         ON referenced_attribute.attrelid = constraint_row.confrelid
        AND referenced_attribute.attnum = referenced_key.attnum
      WHERE namespace_row.nspname = 'auth'
      GROUP BY constraint_row.oid, local_class.relname, referenced_class.relname
      ORDER BY constraint_row.conname`,
  );
  const functions = await queryRows<FunctionCatalogRow>(
    executor,
    `SELECT proc.proname AS function_name,
            pg_get_function_identity_arguments(proc.oid) AS identity_arguments,
            pg_get_function_result(proc.oid) AS return_type,
            language_row.lanname AS language_name,
            pg_get_functiondef(proc.oid) AS definition,
            proc.prosrc AS prosrc,
            proc.provolatile AS volatility,
            proc.proparallel AS parallel_safety,
            proc.prosecdef AS security_definer,
            proc.proleakproof AS leakproof,
            proc.proisstrict AS is_strict,
            proc.proconfig AS config
       FROM pg_proc AS proc
       JOIN pg_namespace AS namespace_row ON namespace_row.oid = proc.pronamespace
       JOIN pg_language AS language_row ON language_row.oid = proc.prolang
      WHERE namespace_row.nspname = 'auth' AND proc.prokind = 'f'
      ORDER BY proc.proname, pg_get_function_identity_arguments(proc.oid)`,
  );
  const types = await queryRows<TypeCatalogRow>(
    executor,
    `SELECT type_row.typname AS type_name,
            type_row.typtype AS type_kind
       FROM pg_type AS type_row
       JOIN pg_namespace AS namespace_row ON namespace_row.oid = type_row.typnamespace
      WHERE namespace_row.nspname = 'auth' AND type_row.typisdefined
      ORDER BY type_row.typname`,
  );
  const triggers = await queryRows<TriggerCatalogRow>(
    executor,
    `SELECT trigger_row.tgname AS trigger_name,
            table_class.relname AS table_name,
            proc.proname AS function_name,
            trigger_row.tgenabled AS enabled,
            trigger_row.tgtype::integer AS trigger_type,
            pg_get_triggerdef(trigger_row.oid, true) AS definition
       FROM pg_trigger AS trigger_row
       JOIN pg_class AS table_class ON table_class.oid = trigger_row.tgrelid
       JOIN pg_namespace AS namespace_row ON namespace_row.oid = table_class.relnamespace
       JOIN pg_proc AS proc ON proc.oid = trigger_row.tgfoid
      WHERE namespace_row.nspname = 'auth' AND NOT trigger_row.tgisinternal
      ORDER BY trigger_row.tgname`,
  );
  const objects = await queryRows<AuthObjectNameRow>(
    executor,
    `SELECT CASE class_row.relkind
              WHEN 'r' THEN 'table'
              WHEN 'p' THEN 'partitioned_table'
              WHEN 'i' THEN 'index'
              WHEN 'S' THEN 'sequence'
              WHEN 'v' THEN 'view'
              WHEN 'm' THEN 'materialized_view'
              WHEN 'c' THEN 'composite_relation'
              WHEN 'f' THEN 'foreign_table'
              ELSE 'relation'
            END AS object_type,
            class_row.relname AS object_name
       FROM pg_class AS class_row
       JOIN pg_namespace AS namespace_row ON namespace_row.oid = class_row.relnamespace
      WHERE namespace_row.nspname = 'auth' AND class_row.relkind IN ('r', 'p', 'i', 'S', 'v', 'm', 'c', 'f')
     UNION ALL
     SELECT 'column' AS object_type, attribute_row.attname AS object_name
       FROM pg_attribute AS attribute_row
       JOIN pg_class AS class_row ON class_row.oid = attribute_row.attrelid
       JOIN pg_namespace AS namespace_row ON namespace_row.oid = class_row.relnamespace
      WHERE namespace_row.nspname = 'auth'
        AND attribute_row.attnum > 0
        AND NOT attribute_row.attisdropped
     UNION ALL
     SELECT 'constraint' AS object_type, constraint_row.conname AS object_name
       FROM pg_constraint AS constraint_row
       JOIN pg_namespace AS namespace_row ON namespace_row.oid = constraint_row.connamespace
      WHERE namespace_row.nspname = 'auth'
     UNION ALL
     SELECT 'function' AS object_type, proc.proname AS object_name
       FROM pg_proc AS proc
       JOIN pg_namespace AS namespace_row ON namespace_row.oid = proc.pronamespace
      WHERE namespace_row.nspname = 'auth'
     UNION ALL
     SELECT 'trigger' AS object_type, trigger_row.tgname AS object_name
       FROM pg_trigger AS trigger_row
       JOIN pg_class AS class_row ON class_row.oid = trigger_row.tgrelid
       JOIN pg_namespace AS namespace_row ON namespace_row.oid = class_row.relnamespace
      WHERE namespace_row.nspname = 'auth' AND NOT trigger_row.tgisinternal
      ORDER BY object_type, object_name`,
  );

  return { tables, columns, indexes, constraints, functions, types, triggers, objects };
}
