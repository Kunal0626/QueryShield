package com.queryshield.normalize;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.function.UnaryOperator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link Normalizer}: each transformation in isolation, the whole
 * pipeline on obfuscated payloads, the hard-negative inputs that must survive
 * unmangled, and the raw-origin offset map.
 */
class NormalizerTest {

    private final Normalizer n = new Normalizer();

    /** Run a single step on a raw string and return just the resulting text. */
    private static String step(UnaryOperator<CharBuf> step, String raw) {
        return step.apply(CharBuf.of(raw)).text();
    }

    @Nested
    @DisplayName("individual steps")
    class Steps {

        @Test
        void plusBecomesSpace() {
            assertEquals("a b c", step(Normalizer::plusToSpace, "a+b+c"));
        }

        @Test
        void percentDecodeBasicAndUtf8() {
            assertEquals("A", step(Normalizer::percentDecodeOnce, "%41"));
            assertEquals("a b", step(Normalizer::percentDecodeOnce, "a%20b"));
            // %C3%A9 is UTF-8 for e-acute; the two escapes decode to one char.
            assertEquals("é", step(Normalizer::percentDecodeOnce, "%C3%A9"));
        }

        @Test
        void percentDecodeLeavesInvalidEscapesAlone() {
            assertEquals("%zz", step(Normalizer::percentDecodeOnce, "%zz"));
            assertEquals("%4", step(Normalizer::percentDecodeOnce, "%4"));
            assertEquals("%", step(Normalizer::percentDecodeOnce, "%"));
        }

        @Test
        void percentDecodeIsBoundedToThreeRounds() {
            // 2x-encoded 'A' decodes fully (within the bound) ...
            assertEquals("A", step(Normalizer::percentDecode, "%2541"));
            // ... but 4x-encoded 'A' needs 4 rounds, so after 3 it is still
            // partially encoded. This is the documented gap, asserted on purpose.
            assertEquals("%41", step(Normalizer::percentDecode, "%25252541"));
        }

        @Test
        void stripNulRemovesNulBytes() {
            assertEquals("ab", step(Normalizer::stripNul, "a\u0000b"));
        }

        @Test
        void nfkcFoldsFullwidthToAscii() {
            // Fullwidth U-N-I-O-N (U+FF35..) folds to ASCII "UNION".
            String fullwidth = "ＵＮＩＯＮ";
            assertEquals("UNION", step(Normalizer::nfkcFold, fullwidth));
        }

        @Test
        void blockCommentBecomesSpace() {
            assertEquals("union select", step(Normalizer::stripComments, "union/**/select"));
            assertEquals("a b", step(Normalizer::stripComments, "a/* hi */b"));
        }

        @Test
        void commentInsideAWordSplitsIt() {
            // Matches MySQL: a comment is a delimiter, so this is two tokens,
            // not the keyword "union".
            assertEquals("un ion", step(Normalizer::stripComments, "un/**/ion"));
        }

        @Test
        void versionedCommentIsUnwrapped() {
            assertEquals("union", step(Normalizer::stripComments, "/*!union*/"));
            assertEquals("union", step(Normalizer::stripComments, "/*!50000union*/"));
        }

        @Test
        void unterminatedCommentRunsToEnd() {
            assertEquals("a ", step(Normalizer::stripComments, "a/*bc"));
        }

        @Test
        void collapseWhitespaceAndTrim() {
            assertEquals("a b c", step(Normalizer::collapseWhitespace, "  a   b\t\n c  "));
        }

        @Test
        void lowercaseIsLocaleIndependent() {
            assertEquals("union", step(Normalizer::lowercase, "UnIoN"));
            // Locale.ROOT behaviour: ASCII 'I' lowercases to 'i', never the
            // dotless Turkish variant that a Turkish locale would produce.
            assertEquals("i", step(Normalizer::lowercase, "I"));
        }
    }

    @Nested
    @DisplayName("full pipeline on obfuscated payloads")
    class Pipeline {

        private String norm(String raw) {
            return n.normalize(raw).value();
        }

        @Test
        void mixedCaseAndEncodedWhitespace() {
            // uNiOn %0a(newline) SeLeCt  ->  union select
            assertEquals("union select", norm("uNiOn%0aSeLeCt"));
        }

        @Test
        void doubleEncodedKeyword() {
            // %2575nion -> %75nion -> union
            assertEquals("union", norm("%2575nion"));
        }

        @Test
        void commentPaddingBetweenTokens() {
            assertEquals("union all select", norm("UNION/**/ALL/**/SELECT"));
        }

        @Test
        void versionedCommentsRejoin() {
            assertEquals("union select", norm("/*!50000UNION*/ /*!50000SELECT*/"));
        }

        @Test
        void fullwidthKeyword() {
            String fullwidth = "ＵＮＩＯＮ"; // UNION
            assertEquals("union", norm(fullwidth));
        }

        @Test
        void plusIsSpaceOnlyWhenRequested() {
            assertEquals("1 1", n.normalize("1+1", true).value());
            assertEquals("1+1", n.normalize("1+1", false).value());
        }
    }

    @Nested
    @DisplayName("hard negatives: benign text must survive unmangled")
    class HardNegatives {

        private String norm(String raw) {
            return n.normalize(raw).value();
        }

        @Test
        void apostropheNamesArePreserved() {
            assertEquals("o'brien", norm("O'Brien"));
            assertEquals("d'souza", norm("D'Souza"));
        }

        @Test
        void tautologyLookingTextIsJustLowercased() {
            // The normalizer does not decide attacks; it must not destroy the
            // quotes a later rule needs to reason about.
            assertEquals("' or '1'='1", norm("' OR '1'='1"));
        }

        @Test
        void ordinaryWordsUnchanged() {
            assertEquals("union station timetable", norm("Union Station Timetable"));
        }
    }

    @Nested
    @DisplayName("offset map back to the raw input")
    class OffsetMap {

        @Test
        void mapsThroughPercentDecoding() {
            // raw:  a % 2 0 b   (indexes 0..4)
            // norm: a   b
            Normalized r = new Normalizer().normalize("a%20b");
            assertEquals("a b", r.value());
            assertArrayEquals(new int[] {0, 1, 4}, r.srcMap());
            assertEquals(4, r.rawIndex(2)); // 'b' came from raw index 4
        }

        @Test
        void mapsThroughCommentRemoval() {
            // raw:  a / * * / b   (indexes 0..5); the comment collapses to one
            // space credited to the comment's opening '/', and 'b' keeps index 5.
            Normalized r = new Normalizer().normalize("a/**/b");
            assertEquals("a b", r.value());
            assertArrayEquals(new int[] {0, 1, 5}, r.srcMap());
        }
    }
}
