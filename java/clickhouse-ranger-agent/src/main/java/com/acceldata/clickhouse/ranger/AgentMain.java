package com.acceldata.clickhouse.ranger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;

/**
 * ClickHouse Ranger agent: hosts the official Ranger plugin and answers authorization
 * requests from ClickHouse over a local TCP socket (see RequestHandler for the protocol).
 *
 * Usage:
 *   java [-Dagent.port=9099] [-Dagent.host=127.0.0.1]
 *        [-Dagent.principal=... -Dagent.keytab=...]          (Kerberos login from keytab; else ticket cache)
 *        -cp conf:target/clickhouse-ranger-agent-0.1.0-SNAPSHOT.jar \
 *        com.acceldata.clickhouse.ranger.AgentMain [--daemon]
 *
 *   --daemon : no console, run until killed (use this when started by ClickHouse / nohup).
 *   default  : also reads debug commands from stdin:
 *       check <user> <rangerAccessType> <db> [table] [column]   (bypasses the privilege mapper)
 *       refresh | quit
 */
public class AgentMain {
    public static void main(String[] args) throws Exception {
        boolean daemon = Arrays.asList(args).contains("--daemon");

        // 1) Must be first: configure Hadoop security BEFORE any Ranger/Hadoop object is created,
        //    otherwise the login user can get cached as SIMPLE.
        loginIfKerberos();

        // 2) Ranger plugin
        ClickHouseAuthorizer authorizer = new ClickHouseAuthorizer();
        authorizer.init();

        // 3) IPC server
        String host = System.getProperty("agent.host", "127.0.0.1");
        int port = Integer.getInteger("agent.port", 9099);
        int maxConnections = Integer.getInteger("agent.maxConnections", 64);
        int idleTimeoutMs = Integer.getInteger("agent.idleTimeoutMs", 300_000);
        IpcServer server = new IpcServer(new RequestHandler(authorizer), host, port, maxConnections, idleTimeoutMs);
        server.start();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.close();
            authorizer.cleanup();
        }));
        System.out.println("READY ipc=" + host + ":" + server.getPort()
            + (daemon ? " (daemon)" : " (console: check <user> <accessType> <db> [table] [column] | refresh | quit)"));

        if (daemon) {
            new CountDownLatch(1).await();   // run until killed
            return;
        }
        consoleLoop(authorizer);
    }

    private static void consoleLoop(ClickHouseAuthorizer authorizer) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = in.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) continue;
            String[] t = line.split("\\s+");
            try {
                switch (t[0]) {
                    case "check": {
                        String user = t[1], access = t[2], db = t[3];
                        String table = t.length > 4 ? t[4] : null;
                        String column = t.length > 5 ? t[5] : null;
                        boolean ok = authorizer.isAllowed(user, null, access, db, table, column);
                        System.out.println(ok ? "ALLOW" : "DENY");
                        break;
                    }
                    case "refresh":
                        authorizer.refreshPolicies();
                        System.out.println("REFRESHED");
                        break;
                    case "quit":
                        return;
                    default:
                        System.out.println("ERROR unknown command: " + t[0]);
                }
            } catch (Exception e) {
                System.out.println("DENY (error: " + e + ")");   // any error is a deny
            }
        }
    }

    /**
     * Applies Hadoop security settings (core-site.xml on the classpath) and, when Kerberos is on,
     * logs in and FAILS FAST if no Kerberos credentials are available. Without this, a bad ticket
     * cache silently falls back to SIMPLE auth and the agent keeps judging with a stale policy cache.
     */
    private static void loginIfKerberos() throws IOException {
        Configuration hconf = new Configuration();   // loads core-site.xml from the classpath
        UserGroupInformation.setConfiguration(hconf);
        if (!UserGroupInformation.isSecurityEnabled()) {
            System.out.println("Hadoop security: SIMPLE (Kerberos not enabled in core-site.xml)");
            return;
        }
        String principal = System.getProperty("agent.principal");
        String keytab = System.getProperty("agent.keytab");
        boolean useKeytab = principal != null && keytab != null;
        if (useKeytab) {
            UserGroupInformation.loginUserFromKeytab(principal, keytab);
        }
        UserGroupInformation ugi = UserGroupInformation.getLoginUser();
        if (!ugi.hasKerberosCredentials()) {
            System.err.println("FATAL: Kerberos is enabled but login failed (auth: "
                + ugi.getAuthenticationMethod() + "). Run kinit, or pass -Dagent.principal/-Dagent.keytab.");
            System.exit(1);
        }
        System.out.println("Kerberos login OK as " + ugi.getUserName()
            + (useKeytab ? " (keytab)" : " (ticket cache)"));
        if (useKeytab) {
            // Keytab TGTs expire; re-login when needed.
            ScheduledExecutorService relogin = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "kerberos-relogin");
                t.setDaemon(true);
                return t;
            });
            relogin.scheduleWithFixedDelay(() -> {
                try {
                    UserGroupInformation.getLoginUser().checkTGTAndReloginFromKeytab();
                } catch (IOException e) {
                    System.err.println("WARN: Kerberos re-login failed: " + e);
                }
            }, 10, 10, TimeUnit.MINUTES);
        }
    }
}
