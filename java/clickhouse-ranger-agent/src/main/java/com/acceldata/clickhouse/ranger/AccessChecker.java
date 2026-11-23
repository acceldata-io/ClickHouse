package com.acceldata.clickhouse.ranger;

import java.util.Set;

/**
 * What the IPC layer needs from the authorization backend.
 * ClickHouseAuthorizer (Ranger) is the real implementation; tests use a fake one.
 */
public interface AccessChecker {
    /**
     * @param accessType Ranger access type (select, insert, update, delete, alter, create, drop, show)
     * @param groups     explicit groups, or null to let the implementation resolve them
     * @return true only if Ranger explicitly allows; everything else is false (fail-closed)
     */
    boolean isAllowed(String user, Set<String> groups, String accessType,
                      String database, String table, String column);

    /** Force a policy download now. */
    void refreshPolicies();
}
