package com.queryshield.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

class JsonParserTest {

    @Test
    void collectsStringValuesWithPaths() {
        Object root = JsonParser.parse("{\"user\":{\"name\":\"alice\"},\"tags\":[\"a\",\"b\"]}");
        Map<String, String> strings = JsonParser.collectStrings(root);
        assertEquals("alice", strings.get("user.name"));
        assertEquals("a", strings.get("tags.0"));
        assertEquals("b", strings.get("tags.1"));
    }

    @Test
    void ignoresNonStringValues() {
        Map<String, String> strings =
                JsonParser.collectStrings(JsonParser.parse("{\"n\":42,\"ok\":true,\"x\":null}"));
        assertTrue(strings.isEmpty());
    }

    @Test
    void handlesEscapes() {
        Object root = JsonParser.parse("{\"q\":\"a\\u0027 OR 1=1\\n\"}");
        assertEquals("a' OR 1=1\n", JsonParser.collectStrings(root).get("q"));
    }

    @Test
    void malformedThrows() {
        assertThrows(JsonParser.JsonException.class, () -> JsonParser.parse("{\"q\":}"));
        assertThrows(JsonParser.JsonException.class, () -> JsonParser.parse("not json"));
    }
}
