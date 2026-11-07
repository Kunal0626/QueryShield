package com.queryshield.proxy;

import com.queryshield.detect.Finding;
import com.queryshield.util.Json;
import java.io.PrintStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Writes exactly one structured JSON line per request decision.
 *
 * <p>One line per decision, machine-parseable, is what makes the proxy
 * operable: you can grep, count, and feed the log to anything. Each record says
 * when, which request (a generated id so a 403's body can be tied back to the
 * log), the verdict and mode, the score, and -- crucially -- which parameter
 * tripped it and what matched, so an alert is actionable instead of just "something
 * looked bad".
 */
public final class DecisionLog {

    private static final int MAX_MATCHES_LOGGED = 10;

    private final PrintStream out;

    public DecisionLog(PrintStream out) {
        this.out = out;
    }

    /** A per-field detection result, kept for logging the worst offenders. */
    public record FieldHit(Field.Location location, String name, int score, List<Finding> findings) {
    }

    public void log(String requestId, ProxyConfig.Mode mode, String verdict, String method,
                    String path, int score, List<FieldHit> hits, Integer upstreamStatus) {
        Map<String, Object> rec = new LinkedHashMap<>();
        rec.put("ts", Instant.now().toString());
        rec.put("rid", requestId);
        rec.put("mode", mode.name().toLowerCase());
        rec.put("verdict", verdict);
        rec.put("method", method);
        rec.put("path", path);
        rec.put("score", score);
        if (upstreamStatus != null) {
            rec.put("upstream_status", upstreamStatus);
        }
        rec.put("matches", matchList(hits));
        out.println(Json.write(rec));
    }

    private static List<Object> matchList(List<FieldHit> hits) {
        List<Object> matches = new ArrayList<>();
        int budget = MAX_MATCHES_LOGGED;
        for (FieldHit hit : hits) {
            for (Finding f : hit.findings()) {
                if (budget-- <= 0) {
                    return matches;
                }
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("loc", hit.location().name().toLowerCase());
                m.put("param", hit.name());
                m.put("source", f.source());
                m.put("label", f.label());
                m.put("weight", f.weight());
                m.put("raw_at", f.rawStart());
                matches.add(m);
            }
        }
        return matches;
    }
}
