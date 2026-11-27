package com.acceldata.clickhouse.ranger;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Maps ClickHouse privilege names to Ranger access types (11 types) and resource types (7 types).
 *
 * Ranger Access Types:
 *   show, select, insert, update, delete, alter, create, drop, source, cluster, serviceadmin
 *
 * Ranger Resource Types:
 *   database, table, column, source-type, named_collection, table_engine, global
 *
 * Names are normalized: upper-case, whitespace -> '_', so "ALTER UPDATE" == "ALTER_UPDATE".
 * CamelCase names (e.g., displaySecretsInShowAndSelect) have no underscores after normalization.
 */
public final class PrivilegeMapper {
    private PrivilegeMapper() {}

    private static final Set<String> SHOW = Set.of(
        "SHOW", "SHOW_DATABASES", "SHOW_TABLES", "SHOW_COLUMNS", "SHOW_DICTIONARIES");

    private static final Set<String> SELECT = Set.of(
        "SELECT", "CHECK", "BACKUP", "DICTGET",
        // Aliases (not counted in leaf total, but mapped for compatibility)
        "DICTHAS", "DICTGETHIERARCHY", "DICTISIN");

    private static final Set<String> INSERT = Set.of("INSERT");

    private static final Set<String> UPDATE = Set.of("ALTER_UPDATE", "TRUNCATE");

    private static final Set<String> DELETE = Set.of("ALTER_DELETE");

    // All ALTER* except UPDATE, DELETE, access management ALTERs, and groups with mixed children
    private static final Set<String> ALTER_EXCLUDED = Set.of(
        "ALTER_UPDATE", "ALTER_DELETE",
        "ALTER_USER", "ALTER_ROLE", "ALTER_QUOTA", "ALTER_ROW_POLICY", "ALTER_SETTINGS_PROFILE",
        // Groups with mixed children (C++ should send leaf privileges)
        "ALTER", "ALTER_TABLE");

    private static final Set<String> CREATE_DB_TABLE = Set.of(
        "CREATE", "CREATE_DATABASE", "CREATE_TABLE", "CREATE_VIEW", "CREATE_DICTIONARY",
        "CREATE_TEMPORARY_TABLE", "CREATE_ARBITRARY_TEMPORARY_TABLE", "UNDROP_TABLE");

    private static final Set<String> CREATE_GLOBAL = Set.of(
        "CREATE_FUNCTION", "CREATE_WORKLOAD", "CREATE_RESOURCE");

    private static final Set<String> DROP_DB_TABLE = Set.of(
        "DROP", "DROP_DATABASE", "DROP_TABLE", "DROP_VIEW", "DROP_DICTIONARY");

    private static final Set<String> DROP_GLOBAL = Set.of(
        "DROP_FUNCTION", "DROP_WORKLOAD", "DROP_RESOURCE");

    // SOURCES: FILE, URL, S3, HDFS, MYSQL, KAFKA, RABBITMQ, etc. (17 types)
    private static final Set<String> SOURCES = Set.of(
        "FILE", "URL", "REMOTE", "MYSQL", "ODBC", "JDBC", "HDFS", "S3", "HIVE",
        "SOURCES", "MONGO", "REDIS", "POSTGRES", "SQLITE", "AZURE", "NATS", "KAFKA", "RABBITMQ");

    // NAMED COLLECTION operations (leaf privileges only, no groups)
    private static final Set<String> NAMED_COLLECTION_OPS = Set.of(
        "CREATE_NAMED_COLLECTION", "DROP_NAMED_COLLECTION",
        "ALTER_NAMED_COLLECTION", "SHOW_NAMED_COLLECTIONS", "SHOW_NAMED_COLLECTIONS_SECRETS",
        "NAMED_COLLECTION");

    // TABLE ENGINE
    private static final Set<String> TABLE_ENGINE = Set.of("TABLE_ENGINE");

    // CLUSTER
    private static final Set<String> CLUSTER = Set.of("CLUSTER");

    // SYSTEM and other serviceadmin privileges (93 total)
    // Note: ROLE_ADMIN is explicitly excluded (always denied per design)
    // Note: ACCESS_MANAGEMENT group is excluded (contains ROLE_ADMIN child)
    private static final Set<String> SERVICEADMIN = Set.of(
        // KILL operations
        "KILL_QUERY", "KILL_TRANSACTION",
        // Display secrets (camelCase → no underscores)
        "DISPLAYSECRETSINSHOWANDSELECT",
        // Access management (CREATE/ALTER/DROP/SHOW for USER, ROLE, QUOTA, SETTINGS_PROFILE, ROW_POLICY)
        // Note: ROLE_ADMIN and ACCESS_MANAGEMENT group are NOT here (explicitly denied)
        "CREATE_USER", "ALTER_USER", "DROP_USER", "SHOW_USERS",
        "CREATE_ROLE", "ALTER_ROLE", "DROP_ROLE", "SHOW_ROLES",
        "CREATE_QUOTA", "ALTER_QUOTA", "DROP_QUOTA", "SHOW_QUOTAS",
        "CREATE_SETTINGS_PROFILE", "ALTER_SETTINGS_PROFILE", "DROP_SETTINGS_PROFILE", "SHOW_SETTINGS_PROFILES",
        "CREATE_ROW_POLICY", "ALTER_ROW_POLICY", "DROP_ROW_POLICY", "SHOW_ROW_POLICIES",
        // Other admin
        "INTROSPECTION", "ADDRESSTOLINE", "ADDRESSTOLINEWITHINLINES", "ADDRESSTOSYMBOL", "DEMANGLE",
        "MOVE_PARTITION_BETWEEN_SHARDS", "ALLOW_SQL_SECURITY_NONE", "SET_DEFINER",
        "SHOW_FILESYSTEM_CACHES"
    );

    // All SYSTEM* privileges start with "SYSTEM"
    private static final String SYSTEM_PREFIX = "SYSTEM";

    static String normalize(String name) {
        return name.trim().toUpperCase(Locale.ROOT).replaceAll("\\s+", "_");
    }

    /**
     * Maps one ClickHouse privilege to Ranger access type.
     * Returns null if unmapped (request will be denied).
     */
    public static String map(String privilege) {
        if (privilege == null) return null;
        String p = normalize(privilege);
        if (p.isEmpty()) return null;

        // Explicitly denied privileges
        if (p.equals("ROLE_ADMIN")) return null;  // Always deny per design

        // Order matters: check specific sets first, then prefixes

        // 1. show
        if (SHOW.contains(p)) return "show";
        if (p.equals("SHOW_NAMED_COLLECTIONS")) return "show";

        // 2. select
        if (SELECT.contains(p)) return "select";

        // 3. insert
        if (INSERT.contains(p)) return "insert";

        // 4. update
        if (UPDATE.contains(p)) return "update";

        // 5. delete
        if (DELETE.contains(p)) return "delete";

        // 6. alter (all ALTER* except UPDATE, DELETE, access management, and groups)
        if (p.startsWith("ALTER_") && !ALTER_EXCLUDED.contains(p)) {
            if (!p.startsWith("ALTER_USER") && !p.startsWith("ALTER_ROLE") &&
                !p.startsWith("ALTER_QUOTA") && !p.startsWith("ALTER_ROW_POLICY") &&
                !p.startsWith("ALTER_SETTINGS_PROFILE")) {
                return "alter";
            }
        }
        if (p.equals("OPTIMIZE")) return "alter";

        // 7. create
        if (CREATE_DB_TABLE.contains(p)) return "create";
        if (CREATE_GLOBAL.contains(p)) return "create";
        if (p.equals("CREATE_NAMED_COLLECTION")) return "create";
        if (TABLE_ENGINE.contains(p)) return "create";

        // 8. drop
        if (DROP_DB_TABLE.contains(p)) return "drop";
        if (DROP_GLOBAL.contains(p)) return "drop";
        if (p.equals("DROP_NAMED_COLLECTION")) return "drop";

        // 9. source
        if (SOURCES.contains(p)) return "source";
        if (p.equals("NAMED_COLLECTION")) return "source";  // use operation

        // 10. cluster
        if (CLUSTER.contains(p)) return "cluster";

        // 11. serviceadmin
        if (p.startsWith(SYSTEM_PREFIX)) return "serviceadmin";
        if (SERVICEADMIN.contains(p)) return "serviceadmin";
        if (p.equals("SHOW_NAMED_COLLECTIONS_SECRETS")) return "serviceadmin";

        // Unmapped
        // Includes: unmapped leaf privileges (ROLE_ADMIN), and groups with mixed children
        // (ALL, NONE, SHOW_ACCESS, ALTER, ALTER_TABLE, etc.)
        // C++ should send leaf privileges; groups are denied except those where all
        // children map to the same access type (SHOW, CREATE, DROP, SOURCES, etc.)
        return null;
    }

    /**
     * Maps a comma-separated privilege list to access types.
     * Returns null if ANY privilege is unmapped (whole request denied).
     */
    public static List<String> mapAll(String commaSeparated) {
        if (commaSeparated == null || commaSeparated.trim().isEmpty()) return null;
        List<String> out = new ArrayList<>();
        for (String p : commaSeparated.split(",")) {
            String a = map(p);
            if (a == null) return null;  // Any unmapped -> deny all
            out.add(a);
        }
        return out;
    }

    /**
     * Determines Ranger resource type based on privilege and ClickHouse objects.
     *
     * Priority:
     *   1. Privilege-based resource types (global, source-type, named_collection, table_engine)
     *   2. Data hierarchy (column > table > database)
     *
     * This ensures CREATE ROW POLICY ON db.t, SYSTEM RESTART REPLICA db.t are global,
     * not table-level, so global serviceadmin policies apply correctly.
     *
     * IMPORTANT:
     * - Call map() first to verify privilege is mapped; unmapped privileges return "database"
     * - Only handles single column; caller must check each column separately for multi-column queries
     * - Empty database: CREATE_TEMPORARY_TABLE may have empty database (verify Ranger "" -> * matching)
     * - Special case: SHOW_NAMED_COLLECTIONS_SECRETS is serviceadmin + named_collection
     *   (service def must allow serviceadmin on named_collection resource)
     */
    public static String getResourceType(String privilege, String database, String table, String column) {
        String p = normalize(privilege);

        // 1. Global privileges (SYSTEM, KILL, ACCESS MANAGEMENT, CREATE/DROP FUNCTION, etc.)
        if (p.startsWith(SYSTEM_PREFIX) || SERVICEADMIN.contains(p) ||
            CREATE_GLOBAL.contains(p) || DROP_GLOBAL.contains(p) || CLUSTER.contains(p)) {
            return "global";
        }

        // 2. Source-type
        if (SOURCES.contains(p)) {
            return "source-type";
        }

        // 3. Named collection
        if (NAMED_COLLECTION_OPS.contains(p)) {
            return "named_collection";
        }

        // 4. Table engine
        if (TABLE_ENGINE.contains(p)) {
            return "table_engine";
        }

        // 5. Data privileges: use column/table/database hierarchy
        // Column-level
        if (column != null && !column.isEmpty() && !column.equals("*")) {
            return "column";
        }

        // Table-level
        if (table != null && !table.isEmpty()) {
            return "table";
        }

        // Database-level (includes CREATE_TEMPORARY_TABLE with empty database)
        if (database != null && !database.isEmpty()) {
            return "database";
        }

        // Default: database (for CREATE DATABASE without specific db name, or temporary tables)
        return "database";
    }
}
