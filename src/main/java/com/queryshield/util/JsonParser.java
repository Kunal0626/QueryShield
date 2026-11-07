package com.queryshield.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A tiny recursive-descent JSON parser, the read side of {@link Json}.
 *
 * <p>The proxy needs it to pull the string values out of a JSON request body so
 * they can be inspected. It parses into plain Java values -- {@code Map} for
 * objects, {@code List} for arrays, {@code String}, {@code Double},
 * {@code Boolean}, {@code null} -- and throws {@link JsonException} on anything
 * malformed, which the caller treats as "not valid JSON, inspect the raw body
 * instead". Hand-written to keep the dependency list to the JDBC driver only;
 * this is plumbing, not the project's core.
 */
public final class JsonParser {

    /** Thrown on malformed JSON. */
    public static final class JsonException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public JsonException(String message) {
            super(message);
        }
    }

    private final String s;
    private int pos;

    private JsonParser(String s) {
        this.s = s;
    }

    /** Parse a JSON document into Java objects. */
    public static Object parse(String json) {
        JsonParser p = new JsonParser(json);
        p.skipWs();
        Object v = p.parseValue();
        p.skipWs();
        if (p.pos != p.s.length()) {
            throw new JsonException("trailing characters at " + p.pos);
        }
        return v;
    }

    /**
     * Collect every string value in a parsed JSON tree, each with the dotted key
     * path that led to it (array indices included), e.g. {@code user.name} or
     * {@code items.0}. Keys themselves are not collected, only values.
     */
    public static Map<String, String> collectStrings(Object root) {
        Map<String, String> out = new LinkedHashMap<>();
        walk("", root, out);
        return out;
    }

    private static void walk(String path, Object node, Map<String, String> out) {
        switch (node) {
            case null -> {
                // JSON null carries no text to inspect.
            }
            case String str -> out.put(path.isEmpty() ? "$" : path, str);
            case Map<?, ?> map -> {
                for (Map.Entry<?, ?> e : map.entrySet()) {
                    String child = path.isEmpty() ? String.valueOf(e.getKey())
                            : path + "." + e.getKey();
                    walk(child, e.getValue(), out);
                }
            }
            case List<?> list -> {
                for (int i = 0; i < list.size(); i++) {
                    walk(path.isEmpty() ? String.valueOf(i) : path + "." + i, list.get(i), out);
                }
            }
            default -> {
                // numbers, booleans, null: not inspected (cannot carry SQL text)
            }
        }
    }

    private Object parseValue() {
        skipWs();
        if (pos >= s.length()) {
            throw new JsonException("unexpected end of input");
        }
        char c = s.charAt(pos);
        return switch (c) {
            case '{' -> parseObject();
            case '[' -> parseArray();
            case '"' -> parseString();
            case 't', 'f' -> parseBoolean();
            case 'n' -> parseNull();
            default -> parseNumber();
        };
    }

    private Map<String, Object> parseObject() {
        Map<String, Object> obj = new LinkedHashMap<>();
        expect('{');
        skipWs();
        if (peek() == '}') {
            pos++;
            return obj;
        }
        while (true) {
            skipWs();
            String key = parseString();
            skipWs();
            expect(':');
            obj.put(key, parseValue());
            skipWs();
            char c = next();
            if (c == '}') {
                return obj;
            }
            if (c != ',') {
                throw new JsonException("expected ',' or '}' at " + (pos - 1));
            }
        }
    }

    private List<Object> parseArray() {
        List<Object> arr = new ArrayList<>();
        expect('[');
        skipWs();
        if (peek() == ']') {
            pos++;
            return arr;
        }
        while (true) {
            arr.add(parseValue());
            skipWs();
            char c = next();
            if (c == ']') {
                return arr;
            }
            if (c != ',') {
                throw new JsonException("expected ',' or ']' at " + (pos - 1));
            }
        }
    }

    private String parseString() {
        expect('"');
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (pos >= s.length()) {
                throw new JsonException("unterminated string");
            }
            char c = s.charAt(pos++);
            if (c == '"') {
                return sb.toString();
            }
            if (c == '\\') {
                sb.append(parseEscape());
            } else {
                sb.append(c);
            }
        }
    }

    private char parseEscape() {
        if (pos >= s.length()) {
            throw new JsonException("bad escape");
        }
        char c = s.charAt(pos++);
        return switch (c) {
            case '"' -> '"';
            case '\\' -> '\\';
            case '/' -> '/';
            case 'b' -> '\b';
            case 'f' -> '\f';
            case 'n' -> '\n';
            case 'r' -> '\r';
            case 't' -> '\t';
            case 'u' -> parseUnicodeEscape();
            default -> throw new JsonException("bad escape \\" + c);
        };
    }

    private char parseUnicodeEscape() {
        if (pos + 4 > s.length()) {
            throw new JsonException("bad unicode escape");
        }
        String hex = s.substring(pos, pos + 4);
        pos += 4;
        try {
            return (char) Integer.parseInt(hex, 16);
        } catch (NumberFormatException e) {
            throw new JsonException("bad unicode escape \\u" + hex);
        }
    }

    private Boolean parseBoolean() {
        if (s.startsWith("true", pos)) {
            pos += 4;
            return Boolean.TRUE;
        }
        if (s.startsWith("false", pos)) {
            pos += 5;
            return Boolean.FALSE;
        }
        throw new JsonException("invalid literal at " + pos);
    }

    private Object parseNull() {
        if (s.startsWith("null", pos)) {
            pos += 4;
            return null;
        }
        throw new JsonException("invalid literal at " + pos);
    }

    private Double parseNumber() {
        int start = pos;
        while (pos < s.length() && "+-0123456789.eE".indexOf(s.charAt(pos)) >= 0) {
            pos++;
        }
        if (pos == start) {
            throw new JsonException("invalid value at " + pos);
        }
        try {
            return Double.parseDouble(s.substring(start, pos));
        } catch (NumberFormatException e) {
            throw new JsonException("invalid number at " + start);
        }
    }

    private void skipWs() {
        while (pos < s.length()) {
            char c = s.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                pos++;
            } else {
                break;
            }
        }
    }

    private char peek() {
        if (pos >= s.length()) {
            throw new JsonException("unexpected end of input");
        }
        return s.charAt(pos);
    }

    private char next() {
        if (pos >= s.length()) {
            throw new JsonException("unexpected end of input");
        }
        return s.charAt(pos++);
    }

    private void expect(char c) {
        if (pos >= s.length() || s.charAt(pos) != c) {
            throw new JsonException("expected '" + c + "' at " + pos);
        }
        pos++;
    }
}
