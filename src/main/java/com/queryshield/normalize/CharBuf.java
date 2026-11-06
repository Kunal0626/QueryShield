package com.queryshield.normalize;

import java.util.Arrays;

/**
 * A growable buffer of characters that remembers, for every character, the
 * index in the ORIGINAL raw input it ultimately came from.
 *
 * <p>Every normalization step reads one {@code CharBuf} and writes a new one.
 * Because the raw-origin index travels with each character through every step,
 * the final buffer can hand back an exact {@link Normalized#srcMap()} with no
 * separate bookkeeping to keep in sync. That is the trick that makes the offset
 * map cheap: it is maintained incrementally instead of reconstructed at the end.
 */
final class CharBuf {

    private final StringBuilder chars = new StringBuilder();
    private final IntList src = new IntList();

    /** Seed a buffer from raw input: character i originates at raw index i. */
    static CharBuf of(String raw) {
        CharBuf b = new CharBuf();
        for (int i = 0; i < raw.length(); i++) {
            b.add(raw.charAt(i), i);
        }
        return b;
    }

    /** Append one character that originated at {@code srcIndex} in the raw input. */
    void add(char c, int srcIndex) {
        chars.append(c);
        src.add(srcIndex);
    }

    /** Append every character of {@code str}, all crediting the same raw origin. */
    void add(String str, int srcIndex) {
        for (int i = 0; i < str.length(); i++) {
            chars.append(str.charAt(i));
            src.add(srcIndex);
        }
    }

    int length() {
        return chars.length();
    }

    char charAt(int i) {
        return chars.charAt(i);
    }

    int src(int i) {
        return src.get(i);
    }

    int codePointAt(int i) {
        return Character.codePointAt(chars, i);
    }

    String text() {
        return chars.toString();
    }

    /** Drop a single trailing space if present (used when trimming whitespace). */
    void trimTrailingSpace() {
        int n = chars.length();
        if (n > 0 && chars.charAt(n - 1) == ' ') {
            chars.deleteCharAt(n - 1);
            src.removeLast();
        }
    }

    Normalized toNormalized() {
        return new Normalized(chars.toString(), src.toArray());
    }

    /**
     * Minimal growable int array. Written by hand rather than using
     * {@code ArrayList<Integer>} to avoid boxing one Integer per character and
     * to keep the intent obvious: this is a parallel index column, not a
     * general collection.
     */
    private static final class IntList {
        private int[] a = new int[16];
        private int size = 0;

        void add(int v) {
            if (size == a.length) {
                a = Arrays.copyOf(a, a.length * 2);
            }
            a[size++] = v;
        }

        int get(int i) {
            return a[i];
        }

        void removeLast() {
            size--;
        }

        int[] toArray() {
            return Arrays.copyOf(a, size);
        }
    }
}
