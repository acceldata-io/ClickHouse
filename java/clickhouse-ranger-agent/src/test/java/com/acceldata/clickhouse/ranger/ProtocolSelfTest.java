package com.acceldata.clickhouse.ranger;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Dependency-free self test (no Ranger/Hadoop needed): java ProtocolSelfTest */
public class ProtocolSelfTest {
    static int failures = 0;

    static void eq(String name, Object expected, Object actual) {
        if (!Objects.equals(expected, actual)) {
            failures++;
            System.out.println("FAIL " + name + ": expected <" + expected + "> but was <" + actual + ">");
        } else {
            System.out.println("ok   " + name);
        }
    }

    /** Fake policy: clickhouse may do everything except drop on db1.secret; admin only select/show; error user throws. */
    static class Fake implements AccessChecker {
        List<String> calls = new ArrayList<>();
        public boolean isAllowed(String user, Set<String> groups, String a, String db, String t, String c) {
            calls.add(user + "/" + a + "/" + db + "/" + t + "/" + c + "/" + groups);
            if (user.equals("boom")) throw new RuntimeException("x");
            if (user.equals("clickhouse")) return !(a.equals("drop") && "secret".equals(t));
            if (user.equals("admin")) return a.equals("select") || a.equals("show");
            return false;
        }
        public void refreshPolicies() { calls.add("refresh"); }
    }

    public static void main(String[] a) throws Exception {
        // mapper
        eq("map SELECT", "select", PrivilegeMapper.map("SELECT"));
        eq("map insert (lowercase)", "insert", PrivilegeMapper.map("insert"));
        eq("map ALTER UPDATE", "update", PrivilegeMapper.map("ALTER UPDATE"));
        eq("map ALTER_DELETE", "delete", PrivilegeMapper.map("ALTER_DELETE"));
        eq("map ALTER ADD COLUMN", "alter", PrivilegeMapper.map("ALTER ADD COLUMN"));
        eq("map ALTER_TABLE", "alter", PrivilegeMapper.map("ALTER_TABLE"));
        eq("map ALTER USER excluded", null, PrivilegeMapper.map("ALTER USER"));
        eq("map CREATE TABLE", "create", PrivilegeMapper.map("CREATE TABLE"));
        eq("map CREATE USER excluded", null, PrivilegeMapper.map("CREATE USER"));
        eq("map DROP DATABASE", "drop", PrivilegeMapper.map("DROP DATABASE"));
        eq("map SHOW TABLES", "show", PrivilegeMapper.map("SHOW TABLES"));
        eq("map SHOW USERS excluded", null, PrivilegeMapper.map("SHOW USERS"));
        eq("map TRUNCATE unmapped", null, PrivilegeMapper.map("TRUNCATE"));
        eq("map SYSTEM RELOAD unmapped", null, PrivilegeMapper.map("SYSTEM RELOAD CONFIG"));
        eq("map ALL unmapped", null, PrivilegeMapper.map("ALL"));
        eq("map null", null, PrivilegeMapper.map(null));
        eq("mapAll list", Arrays.asList("update", "delete"), PrivilegeMapper.mapAll("ALTER UPDATE,ALTER DELETE"));
        eq("mapAll one bad => null", null, PrivilegeMapper.mapAll("SELECT,TRUNCATE"));
        eq("mapAll empty => null", null, PrivilegeMapper.mapAll(" "));

        // handler
        Fake f = new Fake();
        RequestHandler h = new RequestHandler(f);
        eq("PING", "PONG", h.handle("PING"));
        eq("REFRESH", "OK", h.handle("REFRESH"));
        eq("allow", "ALLOW", h.handle("CHECK\tclickhouse\tSELECT\tdb1\tt1\t"));
        eq("deny by policy", "DENY\tdenied by Ranger: drop", h.handle("CHECK\tclickhouse\tDROP TABLE\tdb1\tsecret\t"));
        eq("allow other priv on secret", "ALLOW", h.handle("CHECK\tclickhouse\tSELECT\tdb1\tsecret\t"));
        eq("admin insert denied", "DENY\tdenied by Ranger: insert", h.handle("CHECK\tadmin\tINSERT\tdb1\tt1\t"));
        eq("multi priv all allowed", "ALLOW", h.handle("CHECK\tadmin\tSELECT,SHOW TABLES\tdb1\tt1\t"));
        eq("multi priv one denied", "DENY\tdenied by Ranger: insert", h.handle("CHECK\tadmin\tSELECT,INSERT\tdb1\tt1\t"));
        eq("unmapped privilege", "DENY\tprivilege not supported: TRUNCATE", h.handle("CHECK\tclickhouse\tTRUNCATE\tdb1\tt1\t"));
        eq("no database", true, h.handle("CHECK\tclickhouse\tSELECT\t\t\t").startsWith("DENY\tdatabase required"));
        eq("column without table", true, h.handle("CHECK\tclickhouse\tSELECT\tdb1\t\tc1").startsWith("DENY"));
        eq("too few fields", true, h.handle("CHECK\tclickhouse\tSELECT").startsWith("DENY\tbad request"));
        eq("unknown command", "DENY\tunknown command", h.handle("HELLO"));
        eq("empty line", "DENY\tempty request", h.handle(""));
        eq("backend exception => DENY", "DENY\tinternal error", h.handle("CHECK\tboom\tSELECT\tdb1\tt1\t"));
        f.calls.clear();
        h.handle("CHECK\tclickhouse\tSELECT\tdb1\tt1\tc1\tg1, g2");
        eq("groups passed", 1, f.calls.size());
        eq("call content", true, f.calls.get(0).startsWith("clickhouse/select/db1/t1/c1/[") && f.calls.get(0).contains("g1") && f.calls.get(0).contains("g2"));

        // server over a real socket
        try (IpcServer srv = new IpcServer(h, "127.0.0.1", 0, 4, 2000)) {
            srv.start();
            try (Socket s = new Socket("127.0.0.1", srv.getPort())) {
                OutputStream out = s.getOutputStream();
                BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
                out.write("PING\nCHECK\tclickhouse\tSELECT\tdb1\tt1\t\r\nCHECK\tclickhouse\tDROP\tdb1\tsecret\t\n".getBytes(StandardCharsets.UTF_8));
                out.flush();
                eq("socket PING", "PONG", in.readLine());
                eq("socket CRLF allow", "ALLOW", in.readLine());
                eq("socket deny", "DENY\tdenied by Ranger: drop", in.readLine());
            }
            // oversize line: connection is dropped, never an ALLOW
            try (Socket s = new Socket("127.0.0.1", srv.getPort())) {
                OutputStream out = s.getOutputStream();
                byte[] big = new byte[IpcServer.MAX_LINE_BYTES + 10];
                Arrays.fill(big, (byte) 'a');
                try { out.write(big); out.write('\n'); out.flush(); } catch (IOException ignored) { }
                BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
                String r;
                try { r = in.readLine(); } catch (IOException e) { r = null; }
                eq("oversize line => closed, no ALLOW", null, r);
            }
            // idle timeout closes the connection
            try (Socket s = new Socket("127.0.0.1", srv.getPort())) {
                s.setSoTimeout(5000);
                long t0 = System.currentTimeMillis();
                int r;
                try { r = s.getInputStream().read(); } catch (IOException e) { r = -2; }
                long dt = System.currentTimeMillis() - t0;
                eq("idle timeout closes connection", true, r == -1 && dt >= 1500 && dt < 4500);
            }
        }
        System.out.println(failures == 0 ? "\nALL PASSED" : "\n" + failures + " FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
