package com.queryshield.match;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.queryshield.match.AhoCorasick.Match;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link AhoCorasick}. The core guarantee is checked by a property
 * test: on hundreds of random pattern/text combinations, the automaton must
 * return exactly the same matches as a brute-force {@code indexOf} oracle.
 */
class AhoCorasickTest {

    // --- a brute-force oracle: obviously correct, used to judge the fast one.
    private static List<Match> naive(List<String> patterns, String text) {
        List<Match> matches = new ArrayList<>();
        for (String p : patterns) {
            if (p.isEmpty()) {
                continue;
            }
            int from = 0;
            int idx;
            while ((idx = text.indexOf(p, from)) >= 0) {
                matches.add(new Match(p, idx, idx + p.length()));
                from = idx + 1; // +1, not +p.length(), so overlaps are counted
            }
        }
        return matches;
    }

    private static final Comparator<Match> ORDER = Comparator
            .comparingInt(Match::start)
            .thenComparingInt(Match::end)
            .thenComparing(Match::pattern);

    private static List<Match> sorted(List<Match> in) {
        List<Match> copy = new ArrayList<>(in);
        copy.sort(ORDER);
        return copy;
    }

    @Test
    @DisplayName("classic she/he/his/hers example finds all overlapping matches")
    void classicExample() {
        List<String> patterns = List.of("he", "she", "his", "hers");
        AhoCorasick ac = AhoCorasick.build(patterns);
        List<Match> got = sorted(ac.scan("ushers"));
        // u s h e r s : "she"@1-4, "he"@2-4, "hers"@2-6
        assertEquals(List.of(
                new Match("she", 1, 4),
                new Match("he", 2, 4),
                new Match("hers", 2, 6)), got);
    }

    @Test
    @DisplayName("overlapping repeats of one pattern are all reported")
    void overlappingRepeats() {
        AhoCorasick ac = AhoCorasick.build(List.of("aa"));
        assertEquals(List.of(
                new Match("aa", 0, 2),
                new Match("aa", 1, 3)), sorted(ac.scan("aaa")));
    }

    @Test
    @DisplayName("sql-flavoured signatures match inside a normalized string")
    void sqlFlavoured() {
        List<String> sigs = List.of("union select", "' or ", "--", "sleep(");
        AhoCorasick ac = AhoCorasick.build(sigs);
        String text = "name=' or '1'='1' union select 1,2,3 -- x";
        Set<String> hit = new LinkedHashSet<>();
        for (Match m : ac.scan(text)) {
            hit.add(m.pattern());
        }
        assertTrue(hit.contains("' or "), hit.toString());
        assertTrue(hit.contains("union select"), hit.toString());
        assertTrue(hit.contains("--"), hit.toString());
    }

    @Test
    void noMatchAndEmptyEdgeCases() {
        AhoCorasick ac = AhoCorasick.build(List.of("abc"));
        assertTrue(ac.scan("").isEmpty());
        assertTrue(ac.scan("ab").isEmpty());
        assertEquals(1, ac.scan("zzabczz").size());
        // Empty / null patterns are ignored by build, leaving just the root.
        AhoCorasick none = AhoCorasick.build(java.util.Arrays.asList("", null));
        assertEquals(0, none.patternCount());
        assertTrue(none.scan("anything").isEmpty());
    }

    @RepeatedTest(500)
    @DisplayName("property: agrees with the naive indexOf oracle on random input")
    void agreesWithNaiveOracle(RepetitionInfo info) {
        // Seed by repetition index so any failure is reproducible.
        Random rng = new Random(info.getCurrentRepetition());

        // A small alphabet forces lots of overlaps and suffix relationships,
        // the cases where a naive-per-pattern loop and AC could diverge.
        final String alphabet = "abc";
        int patternCount = 1 + rng.nextInt(5);
        Set<String> patterns = new LinkedHashSet<>();
        for (int i = 0; i < patternCount; i++) {
            patterns.add(randomString(rng, alphabet, 1, 4));
        }
        String text = randomString(rng, alphabet, 0, 30);

        List<String> patternList = new ArrayList<>(patterns);
        AhoCorasick ac = AhoCorasick.build(patternList);

        assertEquals(
                sorted(naive(patternList, text)),
                sorted(ac.scan(text)),
                () -> "patterns=" + patternList + " text=" + text);
    }

    private static String randomString(Random rng, String alphabet, int min, int max) {
        int len = min + rng.nextInt(max - min + 1);
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(alphabet.charAt(rng.nextInt(alphabet.length())));
        }
        return sb.toString();
    }
}
