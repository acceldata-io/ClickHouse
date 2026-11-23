package com.acceldata.clickhouse.ranger;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;

/**
 * Thin wrapper around the official Ranger plugin (RangerBasePlugin).
 * Same pattern as Kudu's RangerKuduAuthorizer. Only stable public Ranger APIs are used,
 * so the same code can be built against Ranger 2.5.0 and 2.9.0 (change ranger.version).
 */
public class ClickHouseAuthorizer implements AccessChecker {
    // Must match the service definition name registered in Ranger Admin.
    static final String SERVICE_TYPE = "clickhouse";
    static final String APP_ID = "clickhouse";

    static final String RES_DATABASE = "database";
    static final String RES_TABLE = "table";
    static final String RES_COLUMN = "column";

    private final RangerBasePlugin plugin = new RangerBasePlugin(SERVICE_TYPE, APP_ID);

    /** Loads ranger-clickhouse-security.xml / ranger-clickhouse-audit.xml from the classpath and starts policy polling. */
    public void init() {
        // Same order as Kudu's RangerKuduAuthorizer: set the audit handler, then init.
        plugin.setResultProcessor(new RangerDefaultAuditHandler());
        plugin.init();
    }

    /** Force a policy download now (useful in tests instead of waiting for the poll interval). */
    @Override
    public void refreshPolicies() {
        plugin.refreshPoliciesAndTags();
    }

    public void cleanup() {
        plugin.cleanup();
    }

    /**
     * @param accessType Ranger access type: select, insert, update, delete, alter, create, drop, show
     * @param database   required
     * @param table      optional (null for database-level checks)
     * @param column     optional (null for table-level checks)
     * @param groups     explicit groups, or null to resolve through Hadoop UserGroupInformation
     */
    @Override
    public boolean isAllowed(String user, Set<String> groups, String accessType,
                             String database, String table, String column) {
        RangerAccessResourceImpl resource = new RangerAccessResourceImpl();
        if (database != null) resource.setValue(RES_DATABASE, database);
        if (table != null) resource.setValue(RES_TABLE, table);
        if (column != null) resource.setValue(RES_COLUMN, column);

        Set<String> userGroups = groups != null ? groups : resolveGroups(user);
        RangerAccessRequestImpl request =
            new RangerAccessRequestImpl(resource, accessType, user, userGroups, null);

        RangerAccessResult result = plugin.isAccessAllowed(request);
        // No matching policy => result is null or not allowed => deny (fail-closed).
        return result != null && result.getIsAllowed();
    }

    private static Set<String> resolveGroups(String user) {
        try {
            String[] names = UserGroupInformation.createRemoteUser(user).getGroupNames();
            return new HashSet<>(java.util.Arrays.asList(names));
        } catch (Exception e) {
            // Group lookup failure must not allow access; user-only policies still work.
            return Collections.emptySet();
        }
    }
}
