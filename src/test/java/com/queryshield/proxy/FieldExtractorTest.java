package com.queryshield.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.queryshield.proxy.Field.Location;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.Test;

class FieldExtractorTest {

    private final ProxyConfig config = ProxyConfig.fromProperties(new Properties());

    private static FieldExtractor.HeaderView headers(Map<String, List<String>> m) {
        return name -> m.getOrDefault(name.toLowerCase(), List.of());
    }

    private static Field find(List<Field> fields, Location loc, String name) {
        return fields.stream()
                .filter(f -> f.location() == loc && f.name().equals(name))
                .findFirst().orElseThrow();
    }

    @Test
    void pathIsAlwaysAFieldAndPlusIsLiteral() {
        List<Field> f = FieldExtractor.extract("/profile", null, null, new byte[0],
                headers(Map.of()), config);
        Field path = find(f, Location.PATH, "path");
        assertEquals("/profile", path.value());
        assertEquals(false, path.plusIsSpace());
    }

    @Test
    void queryValuesKeptEncodedAndPlusIsSpace() {
        List<Field> f = FieldExtractor.extract("/search", "q=a%27+OR+1", null, new byte[0],
                headers(Map.of()), config);
        Field q = find(f, Location.QUERY, "q");
        assertEquals("a%27+OR+1", q.value()); // still encoded; detector decodes
        assertTrue(q.plusIsSpace());
    }

    @Test
    void formBodyParsed() {
        byte[] body = "username=admin%27+--+&password=x".getBytes();
        List<Field> f = FieldExtractor.extract("/login", null,
                "application/x-www-form-urlencoded", body, headers(Map.of()), config);
        assertEquals("admin%27+--+", find(f, Location.FORM, "username").value());
    }

    @Test
    void jsonStringValuesExtractedWithPlusLiteral() {
        byte[] body = "{\"q\":\"' OR 1=1\"}".getBytes();
        List<Field> f = FieldExtractor.extract("/api", null, "application/json", body,
                headers(Map.of()), config);
        Field q = find(f, Location.JSON, "q");
        assertEquals("' OR 1=1", q.value());
        assertEquals(false, q.plusIsSpace());
    }

    @Test
    void malformedJsonFallsBackToRawBody() {
        byte[] body = "{bad json".getBytes();
        List<Field> f = FieldExtractor.extract("/api", null, "application/json", body,
                headers(Map.of()), config);
        assertEquals("{bad json", find(f, Location.JSON, "body").value());
    }

    @Test
    void configuredHeadersInspected() {
        List<Field> f = FieldExtractor.extract("/", null, null, new byte[0],
                headers(Map.of("user-agent", List.of("sqlmap/1.0"))), config);
        assertEquals("sqlmap/1.0", find(f, Location.HEADER, "user-agent").value());
    }
}
