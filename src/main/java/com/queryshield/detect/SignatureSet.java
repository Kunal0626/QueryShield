package com.queryshield.detect;

import com.queryshield.match.AhoCorasick;
import com.queryshield.normalize.Normalized;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The loaded set of attack signatures, compiled into one Aho-Corasick automaton
 * so that scanning a field for all of them is a single linear pass.
 *
 * <p>The signature text file ({@code signatures.txt}) is parsed into
 * {@link Signature} records; the patterns build the automaton, and a lookup map
 * recovers each pattern's weight when a match is reported.
 */
public final class SignatureSet {

    private static final int DEFAULT_WEIGHT = 3;

    private final AhoCorasick automaton;
    private final Map<String, Signature> byPattern;

    private SignatureSet(AhoCorasick automaton, Map<String, Signature> byPattern) {
        this.automaton = automaton;
        this.byPattern = byPattern;
    }

    /** Load the bundled signatures from the classpath resource. */
    public static SignatureSet fromResource(String resourcePath) {
        try (InputStream in = SignatureSet.class.getResourceAsStream(resourcePath)) {
            if (in == null) {
                throw new IllegalStateException("signature resource not found: " + resourcePath);
            }
            return load(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Parse signatures from a "weight|pattern" stream (see signatures.txt). */
    public static SignatureSet load(InputStream in) throws IOException {
        Map<String, Signature> byPattern = new LinkedHashMap<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                String trimmed = line.strip();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                int bar = trimmed.indexOf('|');
                int weight = DEFAULT_WEIGHT;
                String pattern = trimmed;
                if (bar > 0) {
                    weight = Integer.parseInt(trimmed.substring(0, bar).strip());
                    pattern = trimmed.substring(bar + 1);
                }
                // Match lowercase, since v1 lowercases and v2/v3 normalize to
                // lowercase. strip() guards against a stray trailing space in
                // the file turning into a never-matching pattern.
                pattern = pattern.strip().toLowerCase(Locale.ROOT);
                if (!pattern.isEmpty()) {
                    byPattern.put(pattern, new Signature(pattern, weight));
                }
            }
        }
        AhoCorasick automaton = AhoCorasick.build(byPattern.keySet());
        return new SignatureSet(automaton, byPattern);
    }

    /** Number of distinct signatures. */
    public int size() {
        return byPattern.size();
    }

    /**
     * Find every signature occurrence in {@code text}. When {@code norm} is
     * provided, each finding's {@code rawStart} is mapped back to the original
     * input through the normalizer's offset map; otherwise it equals the
     * normalized-text offset.
     */
    public List<Finding> find(String text, Normalized norm) {
        List<Finding> out = new ArrayList<>();
        for (AhoCorasick.Match m : automaton.scan(text)) {
            Signature sig = byPattern.get(m.pattern());
            int rawStart = norm != null ? norm.rawIndex(m.start()) : m.start();
            out.add(new Finding("signature", m.pattern(), sig.weight(), m.start(), m.end(), rawStart));
        }
        return out;
    }
}
