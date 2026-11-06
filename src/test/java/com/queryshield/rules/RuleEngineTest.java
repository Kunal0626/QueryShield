package com.queryshield.rules;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.queryshield.detect.Finding;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class RuleEngineTest {

    private final RuleEngine engine = new RuleEngine();

    /** Rule names that fire for a normalized input (norm map not needed here). */
    private Set<String> firedRules(String normalized) {
        return engine.apply(normalized, null).stream()
                .map(Finding::label)
                .collect(Collectors.toSet());
    }

    @Test
    void unionSelectFiresButUnionStationDoesNot() {
        assertTrue(firedRules("union select 1,2").contains("union-select"));
        assertFalse(firedRules("union station timetable").contains("union-select"));
    }

    @Test
    void stackedQueryFiresButSemicolonProseDoesNot() {
        assertTrue(firedRules("; drop table users").contains("stacked-query"));
        assertFalse(firedRules("hello; world").contains("stacked-query"));
    }

    @Test
    @DisplayName("comment-after-quote catches admin'# but not O'Brien")
    void commentAfterQuote() {
        assertTrue(firedRules("admin'#").contains("comment-after-quote"));
        assertTrue(firedRules("admin' -- ").contains("comment-after-quote"));
        assertFalse(firedRules("o'brien").contains("comment-after-quote"));
    }

    @Test
    @DisplayName("tautology needs SQL context: ' OR 1=1 fires, bare 1=1 does not")
    void tautologyGatedBySqlContext() {
        assertTrue(firedRules("' or 1=1").contains("tautology"));
        assertTrue(firedRules("'1'='1").contains("tautology"));
        assertFalse(firedRules("1=1").contains("tautology"));
        assertFalse(firedRules("the equation 1=1 is always true").contains("tautology"));
    }

    @Test
    void timeFunctionFires() {
        assertTrue(firedRules("sleep(5)").contains("time-function"));
        assertTrue(firedRules("waitfor delay '0:0:5'").contains("time-function"));
    }

    @Test
    void orderByNumberFiresButOrderByNameDoesNot() {
        assertTrue(firedRules("order by 3").contains("order-by-number"));
        assertFalse(firedRules("order by phone").contains("order-by-number"));
    }

    @Test
    @DisplayName("long hex literal fires, short separator hex does not")
    void longHexLiteral() {
        // 0x756e696f6e2073656c656374 == "union select"
        assertTrue(firedRules("0x756e696f6e2073656c656374").contains("long-hex-literal"));
        assertFalse(firedRules("concat(0x3a)").contains("long-hex-literal"));
    }

    @Test
    void unbalancedQuoteIsWeakSignal() {
        List<Finding> f = engine.apply("o'brien", null);
        assertTrue(f.stream().anyMatch(x -> x.label().equals("unbalanced-quote")));
        // and it is low weight, so a lone apostrophe cannot block by itself
        assertTrue(f.stream().filter(x -> x.label().equals("unbalanced-quote"))
                .allMatch(x -> x.weight() <= 2));
    }
}
