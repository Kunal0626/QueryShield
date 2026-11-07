package com.queryshield.proxy;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

/**
 * Proxy settings, loaded from a properties file (see config/queryshield.properties).
 * Keeping these in a file rather than in code is what lets the same build run as
 * a shadow monitor or an active blocker, and lets an operator add allow-listed
 * paths or inspected headers without a recompile.
 */
public record ProxyConfig(
        String listenHost,
        int listenPort,
        URI upstreamBase,
        Mode mode,
        int threshold,
        List<String> inspectHeaders,
        List<String> allowPaths,
        int maxBodyBytes,
        int threads) {

    public enum Mode {
        /** Reject suspicious requests with 403. */
        BLOCK,
        /** Log the decision but forward anyway (shadow mode). */
        MONITOR
    }

    public static ProxyConfig load(Path file) {
        Properties p = new Properties();
        try (InputStream in = Files.newInputStream(file)) {
            p.load(in);
        } catch (IOException e) {
            throw new IllegalStateException("cannot read proxy config " + file, e);
        }
        return fromProperties(p);
    }

    static ProxyConfig fromProperties(Properties p) {
        return new ProxyConfig(
                p.getProperty("listen.host", "127.0.0.1").strip(),
                intProp(p, "listen.port", 8080),
                URI.create(p.getProperty("upstream.base", "http://127.0.0.1:8081").strip()),
                Mode.valueOf(p.getProperty("mode", "block").strip().toUpperCase(Locale.ROOT)),
                intProp(p, "threshold", 3),
                csv(p.getProperty("inspect.headers", "cookie,user-agent,referer")),
                csv(p.getProperty("allow.paths", "/health")),
                intProp(p, "max.body.bytes", 1_048_576),
                intProp(p, "threads", 16));
    }

    private static int intProp(Properties p, String key, int def) {
        String v = p.getProperty(key);
        return v == null || v.isBlank() ? def : Integer.parseInt(v.strip());
    }

    private static List<String> csv(String raw) {
        List<String> out = new ArrayList<>();
        for (String part : raw.split(",")) {
            String t = part.strip().toLowerCase(Locale.ROOT);
            if (!t.isEmpty()) {
                out.add(t);
            }
        }
        return out;
    }
}
