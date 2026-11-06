package com.queryshield.victim;

import com.queryshield.util.Json;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * ============================================================================
 *  !!  VULNERABLE ON PURPOSE  !!   DO NOT DEPLOY.   LOCALHOST (127.0.0.1) ONLY.
 * ============================================================================
 *
 * A deliberately insecure web app that backs the QueryShield demo. It builds
 * SQL by string concatenation so the injection attacks are real, not simulated.
 * It exists so we can (a) show the attacks working and (b) prove the proxy
 * stops them. All data in the database is fake.
 *
 * <p>Endpoints (vulnerable, string-concatenated SQL):
 * <ul>
 *   <li>{@code POST /login}      form fields: username, password  (auth bypass)
 *   <li>{@code GET  /search?q=}  product search by name           (UNION-based)
 *   <li>{@code GET  /profile?id=} user profile by numeric id      (blind / time)
 * </ul>
 *
 * <p>The same three endpoints exist under {@code /safe/...} written with
 * {@link PreparedStatement}, so the correct fix can be shown side by side
 * against the identical attacks.
 *
 * <p>Flags:
 * <ul>
 *   <li>{@code --port=N}    listen port (default 8081)
 *   <li>{@code --props=P}   path to local.properties (default victim/local.properties)
 *   <li>{@code --safe-only} disable the vulnerable endpoints (return 410)
 *   <li>{@code --echo-sql}  include the executed SQL in vulnerable responses
 *                           (teaching aid; real apps never do this)
 * </ul>
 */
public final class VictimApp {

    private static final String BANNER = """
            ============================================================
             QueryShield demo VICTIM app  --  VULNERABLE ON PURPOSE
             Bound to 127.0.0.1 only. Do not deploy. All data is fake.
            ============================================================""";

    private final Db db;
    private final boolean safeOnly;
    private final boolean echoSql;

    private VictimApp(Db db, boolean safeOnly, boolean echoSql) {
        this.db = db;
        this.safeOnly = safeOnly;
        this.echoSql = echoSql;
    }

    public static void main(String[] args) throws IOException {
        int port = intArg(args, "--port=", 8081);
        String props = strArg(args, "--props=", "victim/local.properties");
        boolean safeOnly = hasFlag(args, "--safe-only");
        boolean echoSql = hasFlag(args, "--echo-sql");

        Db db = new Db(Path.of(props));
        db.checkReachable();

        VictimApp app = new VictimApp(db, safeOnly, echoSql);

        // Bind to the loopback address explicitly: this app must never be
        // reachable from another machine.
        InetSocketAddress addr = new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port);
        HttpServer server = HttpServer.create(addr, 0);

        server.createContext("/", app::handleIndex);
        server.createContext("/health", app::handleHealth);
        server.createContext("/login", app.vulnerable(app::vulnLogin));
        server.createContext("/search", app.vulnerable(app::vulnSearch));
        server.createContext("/profile", app.vulnerable(app::vulnProfile));
        server.createContext("/safe/login", app::safeLogin);
        server.createContext("/safe/search", app::safeSearch);
        server.createContext("/safe/profile", app::safeProfile);

        server.start();
        System.out.println(BANNER);
        System.out.println(" listening on http://127.0.0.1:" + port
                + (safeOnly ? "  [--safe-only: vulnerable endpoints disabled]" : ""));
        System.out.println(" try: GET /  for usage. Ctrl-C to stop.");
    }

    // ----------------------------------------------------------------------
    // Vulnerable endpoints. SQL is assembled with '+'. This is the bug, on
    // purpose. A real app would use PreparedStatement (see the /safe versions).
    // ----------------------------------------------------------------------

    /** Wrap a vulnerable handler so --safe-only can switch it off at the door. */
    private HttpHandler vulnerable(HttpHandler h) {
        return exchange -> {
            if (safeOnly) {
                sendJson(exchange, 410, Map.of(
                        "error", true,
                        "message", "vulnerable endpoint disabled (--safe-only)"));
                return;
            }
            h.handle(exchange);
        };
    }

    private void vulnLogin(HttpExchange ex) throws IOException {
        if (!"POST".equals(ex.getRequestMethod())) {
            sendJson(ex, 405, Map.of("error", true, "message", "POST form: username, password"));
            return;
        }
        Map<String, String> form = parseForm(readBody(ex));
        String username = form.getOrDefault("username", "");
        String password = form.getOrDefault("password", "");

        // VULNERABLE: username and password are concatenated straight into SQL.
        String sql = "SELECT id, username, is_admin FROM users "
                + "WHERE username = '" + username + "' "
                + "AND password_hash = SHA2('" + password + "', 256)";

        try (Connection c = db.open();
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(sql)) {
            if (rs.next()) {
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("authenticated", true);
                out.put("id", rs.getObject("id"));
                out.put("username", rs.getObject("username"));
                out.put("is_admin", rs.getObject("is_admin"));
                maybeEchoSql(out, sql);
                sendJson(ex, 200, out);
            } else {
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("authenticated", false);
                maybeEchoSql(out, sql);
                sendJson(ex, 401, out);
            }
        } catch (SQLException e) {
            // VULNERABLE: the raw DB error is returned to the client. This is
            // exactly how error-based injection leaks information.
            sendDbError(ex, e, sql);
        }
    }

    private void vulnSearch(HttpExchange ex) throws IOException {
        String q = queryParam(ex, "q");

        // VULNERABLE: q is concatenated inside a LIKE pattern.
        String sql = "SELECT id, name, price FROM products WHERE name LIKE '%" + q + "%'";

        try (Connection c = db.open();
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(sql)) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("results", rows(rs));
            maybeEchoSql(out, sql);
            sendJson(ex, 200, out);
        } catch (SQLException e) {
            sendDbError(ex, e, sql);
        }
    }

    private void vulnProfile(HttpExchange ex) throws IOException {
        String id = queryParam(ex, "id");

        // VULNERABLE: numeric context, no quotes. id is concatenated directly,
        // so AND/OR/SLEEP() payloads evaluate as SQL.
        String sql = "SELECT id, username, email FROM users WHERE id = " + id;

        try (Connection c = db.open();
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(sql)) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("profiles", rows(rs));
            maybeEchoSql(out, sql);
            sendJson(ex, 200, out);
        } catch (SQLException e) {
            sendDbError(ex, e, sql);
        }
    }

    // ----------------------------------------------------------------------
    // Safe endpoints. Identical behaviour, written with PreparedStatement so
    // the parameter is sent out-of-band and can never change the query's shape.
    // This is the real fix; the proxy is defence in depth on top of it.
    // ----------------------------------------------------------------------

    private void safeLogin(HttpExchange ex) throws IOException {
        if (!"POST".equals(ex.getRequestMethod())) {
            sendJson(ex, 405, Map.of("error", true, "message", "POST form: username, password"));
            return;
        }
        Map<String, String> form = parseForm(readBody(ex));
        String username = form.getOrDefault("username", "");
        String password = form.getOrDefault("password", "");

        String sql = "SELECT id, username, is_admin FROM users "
                + "WHERE username = ? AND password_hash = SHA2(?, 256)";
        try (Connection c = db.open();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, username);
            ps.setString(2, password);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("authenticated", true);
                    out.put("id", rs.getObject("id"));
                    out.put("username", rs.getObject("username"));
                    out.put("is_admin", rs.getObject("is_admin"));
                    sendJson(ex, 200, out);
                } else {
                    sendJson(ex, 401, Map.of("authenticated", false));
                }
            }
        } catch (SQLException e) {
            sendGenericError(ex);
        }
    }

    private void safeSearch(HttpExchange ex) throws IOException {
        String q = queryParam(ex, "q");
        String sql = "SELECT id, name, price FROM products WHERE name LIKE ?";
        try (Connection c = db.open();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, "%" + q + "%");
            try (ResultSet rs = ps.executeQuery()) {
                sendJson(ex, 200, Map.of("results", rows(rs)));
            }
        } catch (SQLException e) {
            sendGenericError(ex);
        }
    }

    private void safeProfile(HttpExchange ex) throws IOException {
        String id = queryParam(ex, "id");
        // Numeric parameter: validate it is actually an integer, then bind it.
        long parsed;
        try {
            parsed = Long.parseLong(id.strip());
        } catch (NumberFormatException e) {
            sendJson(ex, 400, Map.of("error", true, "message", "id must be an integer"));
            return;
        }
        String sql = "SELECT id, username, email FROM users WHERE id = ?";
        try (Connection c = db.open();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setLong(1, parsed);
            try (ResultSet rs = ps.executeQuery()) {
                sendJson(ex, 200, Map.of("profiles", rows(rs)));
            }
        } catch (SQLException e) {
            sendGenericError(ex);
        }
    }

    // ----------------------------------------------------------------------
    // Informational endpoints.
    // ----------------------------------------------------------------------

    private void handleIndex(HttpExchange ex) throws IOException {
        if (!"/".equals(ex.getRequestURI().getPath())) {
            sendJson(ex, 404, Map.of("error", true, "message", "not found"));
            return;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("app", "QueryShield demo victim");
        out.put("warning", "VULNERABLE ON PURPOSE. Localhost only. Fake data.");
        out.put("vulnerable_endpoints", List.of(
                "POST /login (username, password)",
                "GET /search?q=",
                "GET /profile?id="));
        out.put("safe_endpoints", List.of(
                "POST /safe/login", "GET /safe/search?q=", "GET /safe/profile?id="));
        sendJson(ex, 200, out);
    }

    private void handleHealth(HttpExchange ex) throws IOException {
        sendJson(ex, 200, Map.of("status", "ok"));
    }

    // ----------------------------------------------------------------------
    // Helpers.
    // ----------------------------------------------------------------------

    /** Convert a result set to a list of column-ordered maps for JSON output. */
    private static List<Map<String, Object>> rows(ResultSet rs) throws SQLException {
        List<Map<String, Object>> list = new ArrayList<>();
        ResultSetMetaData md = rs.getMetaData();
        int n = md.getColumnCount();
        while (rs.next()) {
            Map<String, Object> row = new LinkedHashMap<>();
            for (int i = 1; i <= n; i++) {
                row.put(md.getColumnLabel(i), normalize(rs.getObject(i)));
            }
            list.add(row);
        }
        return list;
    }

    /** Keep types the JSON writer understands; stringify anything exotic. */
    private static Object normalize(Object v) {
        return switch (v) {
            case null -> null;
            case String s -> s;
            case Number n -> n;
            case Boolean b -> b;
            default -> v.toString();
        };
    }

    private void maybeEchoSql(Map<String, Object> out, String sql) {
        if (echoSql) {
            out.put("debug_sql", sql);
        }
    }

    private void sendDbError(HttpExchange ex, SQLException e, String sql) throws IOException {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("error", true);
        out.put("db_message", e.getMessage()); // leaked on purpose (error-based)
        maybeEchoSql(out, sql);
        sendJson(ex, 500, out);
    }

    private void sendGenericError(HttpExchange ex) throws IOException {
        sendJson(ex, 500, Map.of("error", true, "message", "internal error"));
    }

    private static String queryParam(HttpExchange ex, String name) {
        String raw = ex.getRequestURI().getRawQuery();
        if (raw == null) {
            return "";
        }
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            String k = eq >= 0 ? pair.substring(0, eq) : pair;
            if (decode(k).equals(name)) {
                return eq >= 0 ? decode(pair.substring(eq + 1)) : "";
            }
        }
        return "";
    }

    private static Map<String, String> parseForm(String body) {
        Map<String, String> m = new LinkedHashMap<>();
        if (body == null || body.isEmpty()) {
            return m;
        }
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            String k = eq >= 0 ? pair.substring(0, eq) : pair;
            String v = eq >= 0 ? pair.substring(eq + 1) : "";
            m.put(decode(k), decode(v));
        }
        return m;
    }

    private static String decode(String s) {
        // URLDecoder maps '+' to space and resolves %XX, which is exactly the
        // x-www-form-urlencoded / query-string convention used by both callers.
        return URLDecoder.decode(s, StandardCharsets.UTF_8);
    }

    /** Read the request body, capped so a huge upload cannot exhaust memory. */
    private static String readBody(HttpExchange ex) throws IOException {
        final int cap = 1_048_576; // 1 MB
        try (InputStream in = ex.getRequestBody()) {
            byte[] bytes = in.readNBytes(cap);
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    private static void sendJson(HttpExchange ex, int status, Map<String, Object> body) throws IOException {
        byte[] payload = Json.write(body).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(status, payload.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(payload);
        }
    }

    private static boolean hasFlag(String[] args, String flag) {
        for (String a : args) {
            if (a.equals(flag)) {
                return true;
            }
        }
        return false;
    }

    private static String strArg(String[] args, String prefix, String def) {
        for (String a : args) {
            if (a.startsWith(prefix)) {
                return a.substring(prefix.length());
            }
        }
        return def;
    }

    private static int intArg(String[] args, String prefix, int def) {
        String s = strArg(args, prefix, null);
        return s == null ? def : Integer.parseInt(s);
    }
}
