package com.queryshield.util;

import java.util.List;
import java.util.Map;

/**
 * Minimal JSON serializer.
 *
 * <p>Hand-written on purpose: the project rule is that nothing *core* hides in a
 * library, and while JSON is only plumbing here, pulling in a JSON dependency
 * just to print a handful of fields is not worth it. This covers exactly the
 * value types we produce: String, Number, Boolean, null, Map (object) and List
 * (array). It is a writer only; we never parse untrusted JSON with it.
 *
 * <p>Correctness that matters for a security tool: strings are escaped so a
 * value containing a quote or control character cannot break out of the JSON
 * structure (which would itself be an injection, into our own logs/responses).
 */
public final class Json {

    private Json() {
    }

    /** Serialize {@code value} to a compact JSON string. */
    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value);
        return sb.toString();
    }

    private static void writeValue(StringBuilder sb, Object v) {
        switch (v) {
            case null -> sb.append("null");
            case String s -> writeString(sb, s);
            case Boolean b -> sb.append(b.booleanValue() ? "true" : "false");
            case Number n -> sb.append(n.toString());
            case Map<?, ?> m -> writeObject(sb, m);
            case List<?> l -> writeArray(sb, l);
            // Any other type is rendered via its string form, still escaped.
            default -> writeString(sb, v.toString());
        }
    }

    private static void writeObject(StringBuilder sb, Map<?, ?> m) {
        sb.append('{');
        boolean first = true;
        for (Map.Entry<?, ?> e : m.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            writeString(sb, String.valueOf(e.getKey()));
            sb.append(':');
            writeValue(sb, e.getValue());
        }
        sb.append('}');
    }

    private static void writeArray(StringBuilder sb, List<?> l) {
        sb.append('[');
        for (int i = 0; i < l.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            writeValue(sb, l.get(i));
        }
        sb.append(']');
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    // Escape remaining control characters with a u-escape;
                    // everything else (non-ASCII included) passes through UTF-8.
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }
}
