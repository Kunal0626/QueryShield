package com.queryshield.normalize;

/**
 * The result of normalizing one input: the cleaned-up text, plus a map from
 * each character of that text back to where it came from in the raw input.
 *
 * <p>Why the map matters: the whole point of normalizing is that we match
 * against a string that no longer looks like what the attacker sent (decoded,
 * comment-stripped, lower-cased, whitespace-collapsed). When a signature
 * matches at position {@code p} in {@link #value()}, {@code srcMap[p]} tells us
 * the index in the ORIGINAL request where that character started, so a log or
 * a 403 can point a human at the real bytes instead of at our transformed copy.
 *
 * <p>{@code srcMap.length == value.length()}. For a character that came from a
 * multi-character raw sequence (e.g. the single space decoded from {@code %20},
 * or the one space a run of whitespace collapsed to), the map points at the
 * first raw character of that sequence. Characters that were deleted (NUL
 * bytes, comment bodies) simply have no entry — their raw indices never appear.
 */
public record Normalized(String value, int[] srcMap) {

    public Normalized {
        if (srcMap.length != value.length()) {
            throw new IllegalArgumentException(
                    "srcMap length " + srcMap.length
                    + " != value length " + value.length());
        }
    }

    /** Raw-input index of the character at {@code normIndex} in {@link #value()}. */
    public int rawIndex(int normIndex) {
        return srcMap[normIndex];
    }

    /** Length of the normalized text. */
    public int length() {
        return value.length();
    }
}
