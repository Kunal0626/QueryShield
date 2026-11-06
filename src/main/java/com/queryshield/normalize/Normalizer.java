package com.queryshield.normalize;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Turns a raw request value into a canonical form that is cheap to match
 * signatures against, undoing the tricks attackers use to hide a payload.
 *
 * <p><b>Why normalize at all.</b> {@code %55NION}, {@code UNION/**}{@code /SELECT},
 * fullwidth letters and mixed case are all the same attack to the database but
 * different bytes on the wire. If we matched the raw bytes we would miss every
 * obfuscated variant; if we each wrote our own ad-hoc unescaping we would
 * disagree with each other. One pipeline, applied once, gives every later stage
 * the same clean string.
 *
 * <p><b>Why normalizing is also the most dangerous part.</b> After this runs we
 * and MySQL are two different parsers looking at one string. Every place we
 * decode differently from the backend is a bug: decode too eagerly and we flag
 * innocent text (false positive); decode too little and a payload slips past
 * (bypass). This "parser differential" is called out at each step below, and
 * the known gaps are listed in the README, not hidden.
 *
 * <p><b>Pipeline order</b> (each step is a method; order is deliberate):
 * <ol>
 *   <li>{@code +} to space  -- form/query encoding treats '+' as a space, and
 *       this must happen before percent-decoding so that a literal {@code %2B}
 *       decodes to '+' rather than being read as a space.
 *   <li>percent-decode, up to {@link #MAX_DECODE_ROUNDS} rounds -- catches
 *       double/triple encoding like {@code %2541} -> {@code %41} -> {@code A}.
 *   <li>strip NUL -- removes {@code U+0000} (also catches a decoded {@code %00},
 *       a classic truncation trick).
 *   <li>NFKC fold -- collapses compatibility characters (fullwidth {@code UNION}
 *       to {@code UNION}) so look-alike Unicode cannot disguise keywords.
 *   <li>strip block comments -- {@code /* ... *}{@code /} becomes a single space
 *       (MySQL treats a comment as a delimiter), and MySQL versioned comments
 *       {@code /*! ... *}{@code /} are unwrapped to their contents (MySQL runs
 *       them).
 *   <li>collapse whitespace -- any run of whitespace becomes one space; ends
 *       trimmed.
 *   <li>lowercase -- case-insensitive matching, done per code point with
 *       {@link Character#toLowerCase(int)} so it is locale-independent and
 *       1:1 (keeps the offset map exact).
 * </ol>
 */
public final class Normalizer {

    /**
     * Percent-decoding is repeated to undo multi-level encoding, but only a few
     * times. Unbounded decoding would be its own bug: it would decode text the
     * backend never would (anything containing a literal {@code %25...}),
     * inventing attacks out of ordinary input. Three rounds covers the
     * double/triple encoding seen in practice; a 4x-encoded payload is a
     * documented gap.
     */
    public static final int MAX_DECODE_ROUNDS = 3;

    /** Normalize assuming URL/form encoding (so '+' means space). */
    public Normalized normalize(String raw) {
        return normalize(raw, true);
    }

    /**
     * @param raw        the raw field value (still encoded)
     * @param plusIsSpace whether '+' should be read as a space. True for query
     *                    string and form-urlencoded values; the proxy passes
     *                    false for JSON string values, where '+' is a literal.
     */
    public Normalized normalize(String raw, boolean plusIsSpace) {
        CharBuf b = CharBuf.of(raw);
        if (plusIsSpace) {
            b = plusToSpace(b);
        }
        b = percentDecode(b);
        b = stripNul(b);
        b = nfkcFold(b);
        b = stripComments(b);
        b = collapseWhitespace(b);
        b = lowercase(b);
        return b.toNormalized();
    }

    // ------------------------------------------------------------------ steps
    // Each step is static and takes/returns a CharBuf so it can be unit-tested
    // in isolation and composed without hidden state.

    /** Replace every '+' with a space (x-www-form-urlencoded convention). */
    static CharBuf plusToSpace(CharBuf in) {
        CharBuf out = new CharBuf();
        for (int i = 0; i < in.length(); i++) {
            char c = in.charAt(i);
            out.add(c == '+' ? ' ' : c, in.src(i));
        }
        return out;
    }

    /** Percent-decode repeatedly, stopping when a round changes nothing or after
     *  {@link #MAX_DECODE_ROUNDS}. */
    static CharBuf percentDecode(CharBuf in) {
        CharBuf b = in;
        for (int round = 0; round < MAX_DECODE_ROUNDS; round++) {
            CharBuf next = percentDecodeOnce(b);
            if (next.text().equals(b.text())) {
                return next;
            }
            b = next;
        }
        return b;
    }

    /**
     * One pass of percent-decoding. Consecutive {@code %XX} escapes are gathered
     * into a byte run and decoded together as UTF-8, so a multi-byte character
     * like {@code %C3%A9} ('e-acute') comes out as one character. Every output
     * character from a run is credited to the raw index of the run's first '%'.
     * A '%' not followed by two hex digits is kept literally.
     */
    static CharBuf percentDecodeOnce(CharBuf in) {
        CharBuf out = new CharBuf();
        ByteArrayOutputStream pending = new ByteArrayOutputStream();
        int pendingSrc = -1;
        int i = 0;
        int n = in.length();
        while (i < n) {
            char c = in.charAt(i);
            if (c == '%' && i + 2 < n && isHex(in.charAt(i + 1)) && isHex(in.charAt(i + 2))) {
                if (pending.size() == 0) {
                    pendingSrc = in.src(i);
                }
                pending.write((hex(in.charAt(i + 1)) << 4) | hex(in.charAt(i + 2)));
                i += 3;
            } else {
                flush(out, pending, pendingSrc);
                out.add(c, in.src(i));
                i++;
            }
        }
        flush(out, pending, pendingSrc);
        return out;
    }

    private static void flush(CharBuf out, ByteArrayOutputStream pending, int pendingSrc) {
        if (pending.size() == 0) {
            return;
        }
        // Malformed UTF-8 is replaced with U+FFFD by the String(bytes, UTF_8)
        // contract, which is fine: we only need a stable, lossless-enough view.
        String decoded = new String(pending.toByteArray(), StandardCharsets.UTF_8);
        out.add(decoded, pendingSrc);
        pending.reset();
    }

    /** Remove NUL characters (U+0000). */
    static CharBuf stripNul(CharBuf in) {
        CharBuf out = new CharBuf();
        for (int i = 0; i < in.length(); i++) {
            char c = in.charAt(i);
            if (c != '\u0000') {
                out.add(c, in.src(i));
            }
        }
        return out;
    }

    /**
     * Apply NFKC compatibility folding, one code point at a time.
     *
     * <p>Per code point on purpose: that folds compatibility look-alikes
     * (fullwidth and other presentation forms of ASCII) which is the real
     * evasion vector, while keeping the output length tied to the input so the
     * offset map stays exact. Full multi-code-point NFKC would additionally
     * combine adjacent marks (e.g. 'e' + combining-acute into a single
     * character) -- irrelevant to SQL keywords and not something the backend
     * would read as a keyword either, so skipping it costs no detection and is
     * noted as a deliberate simplification.
     */
    static CharBuf nfkcFold(CharBuf in) {
        CharBuf out = new CharBuf();
        int i = 0;
        int n = in.length();
        while (i < n) {
            int cp = in.codePointAt(i);
            int count = Character.charCount(cp);
            int srcIndex = in.src(i);
            String one = new String(Character.toChars(cp));
            String folded = java.text.Normalizer.normalize(one, java.text.Normalizer.Form.NFKC);
            out.add(folded, srcIndex);
            i += count;
        }
        return out;
    }

    /**
     * Replace block comments with a space, and unwrap MySQL versioned comments.
     *
     * <p>{@code /* ... *}{@code /} becomes a single space because MySQL treats a
     * comment as a token delimiter: {@code UNION/**}{@code /SELECT} is
     * {@code UNION SELECT}, so a space is the faithful translation. (Note a
     * comment inside a keyword, {@code UN/**}{@code /ION}, becomes {@code UN ION}
     * here -- two tokens -- which is exactly what MySQL sees too, so it is not a
     * keyword to either of us.)
     *
     * <p>{@code /*! ... *}{@code /} is a MySQL versioned comment whose contents
     * MySQL actually executes, optionally gated by a version number right after
     * the '!'. We drop the wrapper and that version number and keep the inner
     * text, so {@code /*!50000UNION*}{@code /} becomes {@code UNION}.
     *
     * <p>An unterminated {@code /*} runs to end of input (MySQL ignores the
     * rest); we do the same.
     */
    static CharBuf stripComments(CharBuf in) {
        CharBuf out = new CharBuf();
        int i = 0;
        int n = in.length();
        while (i < n) {
            if (in.charAt(i) == '/' && i + 1 < n && in.charAt(i + 1) == '*') {
                int commentStartSrc = in.src(i);
                int j = i + 2;
                boolean versioned = j < n && in.charAt(j) == '!';
                if (versioned) {
                    j++; // consume '!'
                    while (j < n && isDigit(in.charAt(j))) {
                        j++; // consume the optional version number
                    }
                }
                int close = indexOfClose(in, j); // index of '*' in the closing "*/", or -1
                if (versioned) {
                    int contentEnd = close < 0 ? n : close;
                    for (int k = j; k < contentEnd; k++) {
                        out.add(in.charAt(k), in.src(k));
                    }
                } else {
                    out.add(' ', commentStartSrc);
                }
                i = close < 0 ? n : close + 2; // skip past the closing "*/"
            } else {
                out.add(in.charAt(i), in.src(i));
                i++;
            }
        }
        return out;
    }

    /** Index of the '*' in the next "*​/" at or after {@code from}, else -1. */
    private static int indexOfClose(CharBuf in, int from) {
        for (int k = from; k + 1 < in.length(); k++) {
            if (in.charAt(k) == '*' && in.charAt(k + 1) == '/') {
                return k;
            }
        }
        return -1;
    }

    /**
     * Collapse every run of whitespace to a single space and trim both ends.
     *
     * <p>The whitespace set is exactly the ASCII characters MySQL treats as
     * whitespace (space, tab, newline, carriage return, form feed, vertical
     * tab). We deliberately do NOT use {@link Character#isWhitespace}, which
     * would also fold Unicode separators the backend does not treat as spaces --
     * that would be a parser differential in the wrong direction.
     */
    static CharBuf collapseWhitespace(CharBuf in) {
        CharBuf out = new CharBuf();
        boolean lastWasSpace = false;
        for (int i = 0; i < in.length(); i++) {
            char c = in.charAt(i);
            if (isSqlWhitespace(c)) {
                // Emit one space only between non-space output; this also trims
                // leading whitespace (out is still empty) ...
                if (out.length() > 0 && !lastWasSpace) {
                    out.add(' ', in.src(i));
                    lastWasSpace = true;
                }
            } else {
                out.add(c, in.src(i));
                lastWasSpace = false;
            }
        }
        out.trimTrailingSpace(); // ... and this trims a trailing run.
        return out;
    }

    /** Lowercase per code point: locale-independent and length-preserving. */
    static CharBuf lowercase(CharBuf in) {
        CharBuf out = new CharBuf();
        int i = 0;
        int n = in.length();
        while (i < n) {
            int cp = in.codePointAt(i);
            int count = Character.charCount(cp);
            out.add(new String(Character.toChars(Character.toLowerCase(cp))), in.src(i));
            i += count;
        }
        return out;
    }

    // --------------------------------------------------------------- helpers

    private static boolean isSqlWhitespace(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\u000B';
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static int hex(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        return c - 'A' + 10;
    }
}
