package com.queryshield.proxy;

import com.queryshield.proxy.Field.Location;
import com.queryshield.util.JsonParser;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Breaks a request into the individual values the detector should inspect, one
 * {@link Field} each.
 *
 * <p>Why per value and never the whole request concatenated: scoring one big
 * blob lets unrelated harmless fragments add up into a phantom attack (a
 * User-Agent ending in a quote plus a search for "or" would look like {@code '
 * or}), and it loses the one fact an alert most needs -- <em>which</em>
 * parameter was dirty. Each value is scored on its own.
 *
 * <p>Values are passed through still-encoded; the detector's normalizer owns
 * all decoding, so decoding here would double-decode. The per-location
 * {@code plusIsSpace} flag is set to match how each place is encoded.
 */
public final class FieldExtractor {

    private FieldExtractor() {
    }

    public static List<Field> extract(String path, String rawQuery, String contentType,
                                      byte[] body, HeaderView headers, ProxyConfig config) {
        List<Field> fields = new ArrayList<>();

        // Path: '+' is literal in a path.
        fields.add(new Field(Location.PATH, "path", path, false));

        // Query string: standard x-www-form-urlencoded, so '+' means space.
        if (rawQuery != null && !rawQuery.isEmpty()) {
            for (String[] kv : splitPairs(rawQuery)) {
                fields.add(new Field(Location.QUERY, decodeName(kv[0]), kv[1], true));
            }
        }

        // Body.
        String ct = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        String bodyText = new String(body, StandardCharsets.UTF_8);
        if (ct.contains("application/x-www-form-urlencoded") && !bodyText.isEmpty()) {
            for (String[] kv : splitPairs(bodyText)) {
                fields.add(new Field(Location.FORM, decodeName(kv[0]), kv[1], true));
            }
        } else if (ct.contains("application/json") && !bodyText.isBlank()) {
            addJsonFields(fields, bodyText);
        }

        // Selected headers: '+' is literal in header values.
        for (String name : config.inspectHeaders()) {
            for (String value : headers.values(name)) {
                fields.add(new Field(Location.HEADER, name, value, false));
            }
        }

        return fields;
    }

    private static void addJsonFields(List<Field> fields, String bodyText) {
        try {
            Object root = JsonParser.parse(bodyText);
            Map<String, String> strings = JsonParser.collectStrings(root);
            if (strings.isEmpty()) {
                return;
            }
            // JSON strings are already unescaped by the parser, so '+' is literal
            // and there is nothing more to percent-decode.
            strings.forEach((key, val) -> fields.add(new Field(Location.JSON, key, val, false)));
        } catch (JsonParser.JsonException e) {
            // Not valid JSON despite the content type: inspect the raw body so a
            // malformed-but-malicious payload is not skipped.
            fields.add(new Field(Location.JSON, "body", bodyText, false));
        }
    }

    /** Split "a=1&b=2" into [name, rawValue] pairs without decoding the value. */
    private static List<String[]> splitPairs(String s) {
        List<String[]> pairs = new ArrayList<>();
        for (String pair : s.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            if (eq < 0) {
                pairs.add(new String[] {pair, ""});
            } else {
                pairs.add(new String[] {pair.substring(0, eq), pair.substring(eq + 1)});
            }
        }
        return pairs;
    }

    /** Decode a parameter name for readable logging (the value stays encoded). */
    private static String decodeName(String raw) {
        try {
            return URLDecoder.decode(raw, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return raw;
        }
    }

    /** Minimal case-insensitive header lookup, decoupled from the HTTP server type. */
    public interface HeaderView {
        List<String> values(String name);
    }
}
