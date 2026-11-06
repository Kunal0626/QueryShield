package com.queryshield.detect;

/**
 * Which detection layers are active and how the block decision is made. The
 * named presets are the three configurations compared in the evaluation:
 *
 * <ul>
 *   <li><b>v1</b> signatures only, over the lowercased raw input (no decoding,
 *       comment handling, Unicode folding or whitespace collapse). The naive
 *       baseline.
 *   <li><b>v2</b> signatures over the fully normalized input -- isolates what
 *       the normalizer buys (encoded/comment/obfuscated payloads).
 *   <li><b>v3</b> normalized input + tokenizer rules + a score threshold
 *       (Phase 6) -- adds structure so precision recovers.
 * </ul>
 *
 * @param name      label used in reports
 * @param normalize run the full normalizer (true) or just lowercase (false)
 * @param decision  block on any match, or on score &ge; threshold
 * @param threshold score needed to block when {@code decision == SCORE}
 * @param useRules  run the Phase 6 tokenizer rules (false until Phase 6)
 */
public record DetectorConfig(
        String name,
        boolean normalize,
        Decision decision,
        int threshold,
        boolean useRules) {

    public enum Decision {
        /** Block if at least one signature or rule matched (v1, v2). */
        ANY_MATCH,
        /** Block if the summed weight reaches {@link #threshold()} (v3). */
        SCORE
    }

    public static DetectorConfig v1() {
        return new DetectorConfig("v1-signatures", false, Decision.ANY_MATCH, 1, false);
    }

    public static DetectorConfig v2() {
        return new DetectorConfig("v2-normalized", true, Decision.ANY_MATCH, 1, false);
    }
}
