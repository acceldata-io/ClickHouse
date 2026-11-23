package com.acceldata.clickhouse.ranger;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Wire protocol logic, independent of sockets (so it can be tested without a network).
 *
 * One request per line, fields separated by TAB:
 *   CHECK \t user \t privileges \t database \t table \t column [\t groups]
 *   PING
 *   REFRESH
 *
 *   privileges : comma-separated ClickHouse privilege names, e.g. "SELECT" or "ALTER UPDATE,ALTER DELETE"
 *   database/table/column : empty = not specified
 *   groups     : optional comma-separated group names (empty/missing = let the agent resolve)
 *
 * One response line:
 *   ALLOW
 *   DENY \t reason
 *   PONG | OK
 *
 * Fail-closed: any malformed request, unmapped privilege or internal error is a DENY.
 * With several privileges, ALL of them must be allowed.
 */
public final class RequestHandler {
    private static final Logger LOG = Logger.getLogger(RequestHandler.class.getName());
    private static final boolean LOG_DECISIONS =
        Boolean.parseBoolean(System.getProperty("agent.log.decisions", "true"));

    private final AccessChecker checker;

    public RequestHandler(AccessChecker checker) {
        this.checker = checker;
    }

    public String handle(String line) {
        try {
            if (line == null || line.isEmpty()) return deny("empty request");
            String[] f = line.split("\t", -1);
            switch (f[0]) {
                case "PING":
                    return "PONG";
                case "REFRESH":
                    checker.refreshPolicies();
                    return "OK";
                case "CHECK":
                    return check(f);
                default:
                    return deny("unknown command");
            }
        } catch (Throwable t) {   // never let an error turn into an allow
            LOG.log(Level.WARNING, "request failed, denying", t);
            return deny("internal error");
        }
    }

    private String check(String[] f) {
        if (f.length < 6) return deny("bad request: expected 6 fields");
        String user = f[1].trim();
        String privileges = f[2];
        String database = emptyToNull(f[3]);
        String table = emptyToNull(f[4]);
        String column = emptyToNull(f[5]);
        Set<String> groups = f.length > 6 ? parseGroups(f[6]) : null;

        if (user.isEmpty()) return deny("user required");
        if (database == null) return deny("database required (MVP: global-level checks are not supported)");
        if (table == null && column != null) return deny("column given without table");

        List<String> accessTypes = PrivilegeMapper.mapAll(privileges);
        if (accessTypes == null) {
            decision(user, privileges, database, table, column, "DENY(unmapped)");
            return deny("privilege not supported: " + privileges);
        }
        for (String accessType : accessTypes) {
            if (!checker.isAllowed(user, groups, accessType, database, table, column)) {
                decision(user, privileges, database, table, column, "DENY(" + accessType + ")");
                return deny("denied by Ranger: " + accessType);
            }
        }
        decision(user, privileges, database, table, column, "ALLOW");
        return "ALLOW";
    }

    private static Set<String> parseGroups(String s) {
        if (s == null || s.trim().isEmpty()) return null;
        Set<String> out = new HashSet<>();
        for (String g : Arrays.asList(s.split(","))) {
            if (!g.trim().isEmpty()) out.add(g.trim());
        }
        return out.isEmpty() ? null : out;
    }

    private static String emptyToNull(String s) {
        return (s == null || s.isEmpty()) ? null : s;
    }

    private static String deny(String reason) {
        return "DENY\t" + reason.replace('\t', ' ').replace('\n', ' ');
    }

    private static void decision(String user, String priv, String db, String table, String column, String result) {
        if (!LOG_DECISIONS) return;
        LOG.info("CHECK user=" + user + " priv=[" + priv + "] resource=" + db
            + (table != null ? "." + table : "") + (column != null ? "." + column : "") + " -> " + result);
    }
}
