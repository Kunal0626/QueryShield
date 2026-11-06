package com.queryshield.eval;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Tests for the hand-written CSV field parser's quoting rules. */
class CsvTest {

    @Test
    void plainFields() {
        assertEquals(List.of("a001", "admin' -- ", "attack", "tautology", "test"),
                Csv.parseLine("a001,admin' -- ,attack,tautology,test"));
    }

    @Test
    void quotedFieldWithComma() {
        assertEquals(List.of("b029", "having said that, let's begin", "benign", "prose", "dev"),
                Csv.parseLine("b029,\"having said that, let's begin\",benign,prose,dev"));
    }

    @Test
    void quotedFieldWithDoubledQuotes() {
        // CSV encoding of {"name":"test"} is "{""name"":""test""}"
        assertEquals(List.of("b073", "{\"name\":\"test\"}", "benign", "json_ish", "dev"),
                Csv.parseLine("b073,\"{\"\"name\"\":\"\"test\"\"}\",benign,json_ish,dev"));
    }
}
