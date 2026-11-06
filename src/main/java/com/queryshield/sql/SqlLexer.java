package com.queryshield.sql;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * A small, deliberately error-tolerant SQL lexer for request fragments.
 *
 * <p><b>Why error-tolerant is the whole point.</b> A normal SQL lexer parses a
 * complete, valid statement and throws on anything malformed. We are lexing a
 * <em>parameter value</em>, which is a fragment and is usually malformed on
 * purpose. The two reframings that follow from that:
 *
 * <ul>
 *   <li>An <b>unterminated quote</b> is not an error, it is a signal. In the
 *       vulnerable app the value sits inside {@code '...'}; a lone quote in the
 *       value closes that string and turns the rest into SQL. So when a quote
 *       has no matching close, we emit a {@link TokenKind#QUOTE} token and keep
 *       lexing the remaining characters <em>as SQL</em> -- which is exactly how
 *       the database would then read them. That is what lets us see the comment
 *       in {@code admin'#} or {@code admin'--} instead of hiding it inside a
 *       "string".</li>
 *   <li>We lex structure, not meaning. {@code UNION/**}{@code /SELECT} has
 *       already become {@code union select} by the time the normalizer is done,
 *       so the lexer sees two keywords; benign {@code union station} is a
 *       keyword then an identifier, and the rules can tell them apart.</li>
 * </ul>
 *
 * <p>Input is the already-normalized (decoded, comment-stripped, lower-cased)
 * string, so the lexer only handles line comments ({@code --}, {@code #}) that
 * the normalizer leaves in place, and need not worry about case or block
 * comments.
 */
public final class SqlLexer {

    private static final Set<String> KEYWORDS = Set.of(
            "select", "union", "all", "distinct", "from", "where", "or", "and",
            "order", "by", "group", "having", "limit", "into", "outfile", "dumpfile",
            "insert", "update", "delete", "drop", "create", "alter", "truncate",
            "grant", "exec", "call", "rename", "replace", "shutdown", "values", "set",
            "join", "on", "as", "like", "rlike", "waitfor", "delay",
            "procedure", "analyse", "sleep", "benchmark", "null", "is", "not", "in");

    public List<Token> lex(String s) {
        List<Token> tokens = new ArrayList<>();
        int i = 0;
        int n = s.length();
        while (i < n) {
            char c = s.charAt(i);

            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                i++;
            } else if (c == '\'' || c == '"' || c == '`') {
                i = lexQuote(s, i, tokens);
            } else if (isDigit(c)) {
                i = lexNumber(s, i, tokens);
            } else if (isWordStart(c)) {
                i = lexWord(s, i, tokens);
            } else if (c == '-' && i + 1 < n && s.charAt(i + 1) == '-'
                    && (i + 2 >= n || s.charAt(i + 2) == ' ')) {
                // MySQL line comment: "--" followed by whitespace or end of line.
                // (A "--" wedged between non-spaces, like high--five, is two
                // minus operators, not a comment -- handled by the else below.)
                tokens.add(new Token(TokenKind.COMMENT, s.substring(i), i, n));
                i = n;
            } else if (c == '#') {
                tokens.add(new Token(TokenKind.COMMENT, s.substring(i), i, n));
                i = n;
            } else {
                i = lexOperatorOrPunct(s, i, tokens);
            }
        }
        return tokens;
    }

    /**
     * Lex a quoted string. If a matching close quote is found it is a terminated
     * {@link TokenKind#STRING}; otherwise it is a breakout {@link TokenKind#QUOTE}
     * and we return the index just past the quote so lexing resumes as SQL.
     * Handles both escape conventions MySQL accepts: a doubled quote
     * ({@code ''}) and a backslash escape ({@code \'}).
     */
    private static int lexQuote(String s, int start, List<Token> tokens) {
        char q = s.charAt(start);
        int n = s.length();
        int j = start + 1;
        while (j < n) {
            char c = s.charAt(j);
            if (c == '\\' && j + 1 < n) {
                j += 2; // backslash escape: skip the escaped char
            } else if (c == q) {
                if (j + 1 < n && s.charAt(j + 1) == q) {
                    j += 2; // doubled quote: an escaped quote inside the string
                } else {
                    // Found the close.
                    tokens.add(new Token(TokenKind.STRING, s.substring(start + 1, j), start, j + 1));
                    return j + 1;
                }
            } else {
                j++;
            }
        }
        // No close: breakout quote. Emit it and resume lexing right after it.
        tokens.add(new Token(TokenKind.QUOTE, String.valueOf(q), start, start + 1));
        return start + 1;
    }

    private static int lexNumber(String s, int start, List<Token> tokens) {
        int n = s.length();
        int j = start;
        if (s.charAt(j) == '0' && j + 1 < n && s.charAt(j + 1) == 'x') {
            j += 2;
            while (j < n && isHex(s.charAt(j))) {
                j++;
            }
        } else {
            while (j < n && (isDigit(s.charAt(j)) || s.charAt(j) == '.')) {
                j++;
            }
        }
        tokens.add(new Token(TokenKind.NUMBER, s.substring(start, j), start, j));
        return j;
    }

    private int lexWord(String s, int start, List<Token> tokens) {
        int n = s.length();
        int j = start;
        while (j < n && isWordPart(s.charAt(j))) {
            j++;
        }
        String word = s.substring(start, j);
        TokenKind kind = KEYWORDS.contains(word) ? TokenKind.KEYWORD : TokenKind.IDENT;
        tokens.add(new Token(kind, word, start, j));
        return j;
    }

    private static int lexOperatorOrPunct(String s, int start, List<Token> tokens) {
        int n = s.length();
        char c = s.charAt(start);
        if (c == '(' || c == ')' || c == ',' || c == ';' || c == '.') {
            tokens.add(new Token(TokenKind.PUNCT, String.valueOf(c), start, start + 1));
            return start + 1;
        }
        // Two-character operators first.
        if (start + 1 < n) {
            String two = s.substring(start, start + 2);
            if (two.equals("<=") || two.equals(">=") || two.equals("<>") || two.equals("!=")
                    || two.equals("||") || two.equals("&&")) {
                tokens.add(new Token(TokenKind.OPERATOR, two, start, start + 2));
                return start + 2;
            }
        }
        if ("=<>!|&+-*/%~^".indexOf(c) >= 0) {
            tokens.add(new Token(TokenKind.OPERATOR, String.valueOf(c), start, start + 1));
            return start + 1;
        }
        // Unknown single character (stray punctuation/unicode): skip it.
        return start + 1;
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    private static boolean isHex(char c) {
        return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static boolean isWordStart(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '@';
    }

    private static boolean isWordPart(char c) {
        return isWordStart(c) || isDigit(c);
    }
}
