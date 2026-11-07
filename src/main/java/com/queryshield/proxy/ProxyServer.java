package com.queryshield.proxy;

import com.queryshield.detect.Detector;
import com.queryshield.detect.DetectorConfig;
import com.queryshield.detect.SignatureSet;
import com.queryshield.detect.Verdict;
import com.queryshield.proxy.DecisionLog.FieldHit;
import com.queryshield.util.Json;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;

/**
 * QueryShield reverse proxy.
 *
 * <p>Listens on the configured port, inspects each request with the shared
 * {@link Detector}, and -- unless it blocks -- forwards it to the upstream app
 * and relays the response. Forwarding correctness ({@link Forwarder}) comes
 * first; inspection sits in front of it.
 *
 * <p>Per request: read (and cap) the body, exempt allow-listed paths, extract
 * fields, score each field independently, then either 403 (block mode) or
 * forward (monitor mode, or clean). Every outcome is one JSON line via
 * {@link DecisionLog}.
 *
 * <p>Run: {@code make proxy}  (override config with {@code ARGS=--config=...}).
 */
public final class ProxyServer {

    private final ProxyConfig config;
    private final Detector detector;
    private final Forwarder forwarder;
    private final DecisionLog log;

    public ProxyServer(ProxyConfig config) {
        this.config = config;
        this.detector = new Detector(
                DetectorConfig.v3(config.threshold()),
                SignatureSet.fromResource("/signatures.txt"));
        this.forwarder = new Forwarder(config.upstreamBase());
        this.log = new DecisionLog(System.out);
    }

    public static void main(String[] args) throws Exception {
        Path cfgPath = Path.of(arg(args, "--config=", "config/queryshield.properties"));
        ProxyConfig config = ProxyConfig.load(cfgPath);
        new ProxyServer(config).start();
    }

    public void start() throws Exception {
        InetSocketAddress addr = new InetSocketAddress(
                InetAddress.getByName(config.listenHost()), config.listenPort());
        HttpServer server = HttpServer.create(addr, 0);
        server.createContext("/", this::handle);
        server.setExecutor(Executors.newFixedThreadPool(config.threads()));
        server.start();
        System.out.println("QueryShield proxy listening on http://"
                + config.listenHost() + ":" + config.listenPort()
                + " -> " + config.upstreamBase()
                + "  [mode=" + config.mode().name().toLowerCase()
                + ", threshold=" + config.threshold() + "]");
    }

    private void handle(HttpExchange ex) {
        String rid = UUID.randomUUID().toString().substring(0, 8);
        String method = ex.getRequestMethod();
        String path = ex.getRequestURI().getPath();
        String rawQuery = ex.getRequestURI().getRawQuery();
        try {
            byte[] body = readBodyCapped(ex.getRequestBody(), config.maxBodyBytes());
            if (body == null) {
                respondJson(ex, 413, Map.of("request_id", rid, "error", "request body too large"));
                log.log(rid, config.mode(), "oversize", method, path, 0, List.of(), null);
                return;
            }

            if (isAllowListed(path)) {
                forwardAndRelay(ex, rid, method, path, rawQuery, body, "allow-exempt");
                return;
            }

            // Inspect every field independently.
            String contentType = first(ex.getRequestHeaders(), "Content-Type");
            FieldExtractor.HeaderView headers = name -> {
                List<String> v = ex.getRequestHeaders().get(name);
                return v == null ? List.of() : v;
            };
            List<Field> fields = FieldExtractor.extract(path, rawQuery, contentType, body, headers, config);

            boolean blocked = false;
            int maxScore = 0;
            List<FieldHit> hits = new ArrayList<>();
            for (Field f : fields) {
                Verdict v = detector.inspect(f.name(), f.value(), f.plusIsSpace());
                if (!v.findings().isEmpty()) {
                    hits.add(new FieldHit(f.location(), f.name(), v.score(), v.findings()));
                }
                maxScore = Math.max(maxScore, v.score());
                blocked |= v.block();
            }

            if (blocked && config.mode() == ProxyConfig.Mode.BLOCK) {
                respondJson(ex, 403, Map.of(
                        "request_id", rid,
                        "error", "request blocked by QueryShield",
                        "score", maxScore));
                log.log(rid, config.mode(), "block", method, path, maxScore, hits, null);
                return;
            }

            // Monitor mode, or a clean request: forward.
            String verdict = blocked ? "would_block" : "allow";
            forwardAndRelay(ex, rid, method, path, rawQuery, body, verdict, maxScore, hits);

        } catch (Exception e) {
            // Any failure (I/O, parsing, upstream) becomes a clean error response
            // and a logged line, never a leaked stack trace to the client.
            safeError(ex, rid, method, path);
        } finally {
            ex.close();
        }
    }

    // Allow-listed / clean / monitor path with no findings to report.
    private void forwardAndRelay(HttpExchange ex, String rid, String method, String path,
                                 String rawQuery, byte[] body, String verdict) {
        forwardAndRelay(ex, rid, method, path, rawQuery, body, verdict, 0, List.of());
    }

    private void forwardAndRelay(HttpExchange ex, String rid, String method, String path,
                                 String rawQuery, byte[] body, String verdict,
                                 int score, List<FieldHit> hits) {
        try {
            Forwarder.Response up = forwarder.forward(
                    method, path, rawQuery, ex.getRequestHeaders(), body);
            relay(ex, up);
            log.log(rid, config.mode(), verdict, method, path, score, hits, up.status());
        } catch (Exception e) {
            respondJsonQuiet(ex, 502, Map.of("request_id", rid, "error", "upstream unavailable"));
            log.log(rid, config.mode(), "upstream_error", method, path, score, hits, null);
        }
    }

    private static void relay(HttpExchange ex, Forwarder.Response up) throws java.io.IOException {
        Headers out = ex.getResponseHeaders();
        for (Map.Entry<String, List<String>> e : up.headers().entrySet()) {
            out.put(e.getKey(), e.getValue());
        }
        byte[] b = up.body();
        if (b != null && b.length > 0) {
            ex.sendResponseHeaders(up.status(), b.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(b);
            }
        } else {
            ex.sendResponseHeaders(up.status(), -1); // no body
        }
    }

    private boolean isAllowListed(String path) {
        for (String prefix : config.allowPaths()) {
            // Exact match, or a path segment under the prefix (so /health matches
            // /health and /health/live, but not /healthcheck).
            if (path.equals(prefix) || path.startsWith(prefix + "/")) {
                return true;
            }
        }
        return false;
    }

    /** Read up to {@code max} bytes; return null if the body is larger. */
    private static byte[] readBodyCapped(InputStream in, int max) throws java.io.IOException {
        byte[] bytes = in.readNBytes(max + 1);
        return bytes.length > max ? null : bytes;
    }

    private static void respondJson(HttpExchange ex, int status, Map<String, Object> body)
            throws java.io.IOException {
        byte[] payload = Json.write(body).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(status, payload.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(payload);
        }
    }

    private static void respondJsonQuiet(HttpExchange ex, int status, Map<String, Object> body) {
        try {
            respondJson(ex, status, body);
        } catch (java.io.IOException ignored) {
            // client went away; nothing to do
        }
    }

    private void safeError(HttpExchange ex, String rid, String method, String path) {
        respondJsonQuiet(ex, 500, Map.of("request_id", rid, "error", "proxy error"));
        log.log(rid, config.mode(), "error", method, path, 0, List.of(), null);
    }

    private static String first(Headers headers, String name) {
        List<String> v = headers.get(name);
        return v == null || v.isEmpty() ? null : v.get(0);
    }

    private static String arg(String[] args, String prefix, String def) {
        for (String a : args) {
            if (a.startsWith(prefix)) {
                return a.substring(prefix.length());
            }
        }
        return def;
    }
}
