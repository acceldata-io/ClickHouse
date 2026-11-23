package com.acceldata.clickhouse.ranger;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Maps ClickHouse leaf privilege names (as sent by the C++ hook) to Ranger access types.
 * Anything not mapped returns null and the request is DENIED (MVP rule: unmapped => deny).
 *
 * Names are normalized first: upper-case, whitespace -> '_', so "ALTER UPDATE" == "ALTER_UPDATE".
 *
 * MVP mapping:
 *   SELECT                              -> select
 *   INSERT                              -> insert
 *   ALTER_UPDATE                        -> update
 *   ALTER_DELETE                        -> delete
 *   ALTER, ALTER_* (all other ALTER_*)  -> alter     (except access-management ALTERs, below)
 *   CREATE, CREATE_DATABASE/TABLE/VIEW/DICTIONARY -> create
 *   DROP,   DROP_DATABASE/TABLE/VIEW/DICTIONARY   -> drop
 *   SHOW,   SHOW_DATABASES/TABLES/COLUMNS/DICTIONARIES -> show
 * Not mapped (denied): TRUNCATE, OPTIMIZE, UNDROP, BACKUP, KILL, SYSTEM_*, SOURCES,
 *   ACCESS MANAGEMENT (CREATE_USER, ALTER_USER, GRANT, ...), and anything unknown.
 */
public final class PrivilegeMapper {
    private PrivilegeMapper() {}

    private static final Set<String> CREATE = Set.of(
        "CREATE", "CREATE_DATABASE", "CREATE_TABLE", "CREATE_VIEW", "CREATE_DICTIONARY");
    private static final Set<String> DROP = Set.of(
        "DROP", "DROP_DATABASE", "DROP_TABLE", "DROP_VIEW", "DROP_DICTIONARY");
    private static final Set<String> SHOW = Set.of(
        "SHOW", "SHOW_DATABASES", "SHOW_TABLES", "SHOW_COLUMNS", "SHOW_DICTIONARIES");
    // ALTER_* names that are access management, not data/DDL on tables
    private static final Set<String> ALTER_EXCLUDED = Set.of(
        "ALTER_USER", "ALTER_ROLE", "ALTER_QUOTA", "ALTER_ROW_POLICY",
        "ALTER_SETTINGS_PROFILE", "ALTER_NAMED_COLLECTION");

    static String normalize(String name) {
        return name.trim().toUpperCase(Locale.ROOT).replaceAll("\\s+", "_");
    }

    /** Returns the Ranger access type for one ClickHouse privilege, or null if unmapped. */
    public static String map(String privilege) {
        if (privilege == null) return null;
        String p = normalize(privilege);
        if (p.isEmpty()) return null;
        switch (p) {
            case "SELECT": return "select";
            case "INSERT": return "insert";
            case "ALTER_UPDATE": return "update";
            case "ALTER_DELETE": return "delete";
            default: break;
        }
        if (CREATE.contains(p)) return "create";
        if (DROP.contains(p)) return "drop";
        if (SHOW.contains(p)) return "show";
        if ((p.equals("ALTER") || p.startsWith("ALTER_")) && !ALTER_EXCLUDED.contains(p)) return "alter";
        return null;
    }

    /**
     * Maps a comma-separated list. Returns the access types (same order), or null if the list is empty
     * or ANY privilege is unmapped (the whole request is then denied).
     */
    public static List<String> mapAll(String commaSeparated) {
        if (commaSeparated == null || commaSeparated.trim().isEmpty()) return null;
        List<String> out = new ArrayList<>();
        for (String p : commaSeparated.split(",")) {
            String a = map(p);
            if (a == null) return null;
            out.add(a);
        }
        return out;
    }
}
