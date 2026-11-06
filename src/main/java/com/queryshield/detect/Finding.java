package com.queryshield.detect;

/**
 * One reason a value looked malicious: a signature that matched or (Phase 6) a
 * rule that fired.
 *
 * @param source    "signature" or the rule name
 * @param label     the matched pattern, or the rule's description
 * @param weight    contribution to the score
 * @param normStart start offset in the normalized text (inclusive)
 * @param normEnd   end offset in the normalized text (exclusive)
 * @param rawStart  start offset mapped back to the original raw input, so a log
 *                  can point at the real bytes the client sent
 */
public record Finding(
        String source,
        String label,
        int weight,
        int normStart,
        int normEnd,
        int rawStart) {
}
