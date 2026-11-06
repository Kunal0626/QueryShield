package com.queryshield.rules;

import com.queryshield.detect.Finding;
import com.queryshield.normalize.Normalized;
import com.queryshield.sql.SqlLexer;
import com.queryshield.sql.Token;
import com.queryshield.sql.TokenKind;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Structural rules over the token stream. Where a signature asks "does this
 * substring appear?", a rule asks "do these tokens stand in this relationship?"
 * -- which is what lets the detector tell an attack from benign text that
 * merely contains the same words.
 *
 * <p>The point of each rule, with the hard negative it is built to respect:
 * <ul>
 *   <li><b>union-select</b>: keyword UNION then SELECT. Benign "union station"
 *       is UNION then an identifier, so it does not fire.
 *   <li><b>stacked-query</b>: ';' then a DML/DDL keyword. Benign "hello; world"
 *       is ';' then an identifier.
 *   <li><b>comment-after-quote</b>: a quote (usually a breakout) followed by a
 *       line comment. Catches {@code admin'#} / {@code admin'--}; benign
 *       {@code O'Brien} has no comment after its quote.
 *   <li><b>tautology</b>: an always-true comparison (equal operands), but only
 *       when gated by SQL context (an OR/AND, or a quote). So {@code ' OR 1=1}
 *       fires while the benign bare maths {@code 1=1} does not.
 *   <li><b>time-function</b>: sleep()/benchmark()/pg_sleep()/WAITFOR DELAY.
 *   <li><b>information-schema</b>: a read of the schema catalogue.
 *   <li><b>order-by-number</b>: ORDER BY &lt;number&gt;, i.e. column-count
 *       probing. Benign "order by phone" is ORDER BY identifier.
 *   <li><b>unbalanced-quote</b>: a breakout quote exists. A soft signal (low
 *       weight) because legitimate names like {@code O'Brien} also trip it.
 * </ul>
 *
 * <p>Each rule contributes at most once, with a weight; the detector sums the
 * rule and signature weights and blocks on a tuned threshold.
 */
public final class RuleEngine {

    // Weights. Strong = a near-certain attack shape; weak = also seen in benign
    // text, so it should not block on its own.
    static final int W_UNION_SELECT = 5;
    static final int W_STACKED = 5;
    static final int W_COMMENT_AFTER_QUOTE = 4;
    static final int W_TAUTOLOGY = 4;
    static final int W_TIME_FN = 4;
    static final int W_INFO_SCHEMA = 3;
    static final int W_ORDER_BY_NUMBER = 3;
    static final int W_LONG_HEX = 3;
    static final int W_UNBALANCED_QUOTE = 2;

    // A hex literal this long (>= 8 bytes) in user input is almost always an
    // encoded payload, e.g. 0x756e696f6e2073656c656374 is "union select".
    // Short hex (0x3a as a separator) stays weak via the 0x signature instead.
    private static final int LONG_HEX_MIN_LEN = 18; // "0x" + 16 hex digits

    private static final Set<String> DML_DDL = Set.of(
            "select", "insert", "update", "delete", "drop", "create", "alter",
            "truncate", "grant", "exec", "call", "rename", "replace", "shutdown", "set");

    private static final Set<String> TIME_FUNCTIONS = Set.of(
            "sleep", "benchmark", "pg_sleep", "waitfor");

    private final SqlLexer lexer = new SqlLexer();

    /** Apply all rules to the normalized text; returns one finding per rule hit. */
    public List<Finding> apply(String normalizedText, Normalized norm) {
        List<Token> t = lexer.lex(normalizedText);
        List<Finding> out = new ArrayList<>();
        add(out, unionSelect(t), "union-select", W_UNION_SELECT, norm);
        add(out, stackedQuery(t), "stacked-query", W_STACKED, norm);
        add(out, commentAfterQuote(t), "comment-after-quote", W_COMMENT_AFTER_QUOTE, norm);
        add(out, tautology(t), "tautology", W_TAUTOLOGY, norm);
        add(out, timeFunction(t), "time-function", W_TIME_FN, norm);
        add(out, informationSchema(t), "information-schema", W_INFO_SCHEMA, norm);
        add(out, orderByNumber(t), "order-by-number", W_ORDER_BY_NUMBER, norm);
        add(out, longHexLiteral(t), "long-hex-literal", W_LONG_HEX, norm);
        add(out, unbalancedQuote(t), "unbalanced-quote", W_UNBALANCED_QUOTE, norm);
        return out;
    }

    private static void add(List<Finding> out, Token hit, String name, int weight, Normalized norm) {
        if (hit == null) {
            return;
        }
        int rawStart = norm != null ? norm.rawIndex(hit.start()) : hit.start();
        out.add(new Finding("rule:" + name, name, weight, hit.start(), hit.end(), rawStart));
    }

    // ------------------------------------------------------------------ rules

    private static Token unionSelect(List<Token> t) {
        for (int i = 0; i < t.size(); i++) {
            if (isKeyword(t, i, "union")) {
                int j = i + 1;
                while (isKeyword(t, j, "all") || isKeyword(t, j, "distinct")) {
                    j++;
                }
                if (isKeyword(t, j, "select")) {
                    return t.get(i);
                }
            }
        }
        return null;
    }

    private static Token stackedQuery(List<Token> t) {
        for (int i = 0; i < t.size() - 1; i++) {
            Token tk = t.get(i);
            if (tk.kind() == TokenKind.PUNCT && tk.text().equals(";")) {
                Token next = t.get(i + 1);
                if (next.kind() == TokenKind.KEYWORD && DML_DDL.contains(next.text())) {
                    return tk;
                }
            }
        }
        return null;
    }

    private static Token commentAfterQuote(List<Token> t) {
        int firstComment = -1;
        for (int i = 0; i < t.size(); i++) {
            if (t.get(i).kind() == TokenKind.COMMENT) {
                firstComment = i;
                break;
            }
        }
        if (firstComment < 0) {
            return null;
        }
        for (int k = 0; k < firstComment; k++) {
            TokenKind kind = t.get(k).kind();
            if (kind == TokenKind.QUOTE || kind == TokenKind.STRING) {
                return t.get(k);
            }
        }
        return null;
    }

    private static Token tautology(List<Token> t) {
        if (!hasSqlContext(t)) {
            return null; // bare maths like "1=1" is not an attack
        }
        for (int i = 0; i < t.size(); i++) {
            Token tk = t.get(i);
            if (tk.kind() == TokenKind.OPERATOR && tk.text().equals("=")) {
                String left = operand(t, i, -1);
                String right = operand(t, i, +1);
                if (left != null && left.equals(right)) {
                    return tk;
                }
            }
        }
        return null;
    }

    /** Operand text next to position {@code i} in direction {@code dir}, seeing
     *  through a transparent breakout quote (so '1'='1 compares 1 with 1). */
    private static String operand(List<Token> t, int i, int dir) {
        int j = i + dir;
        if (j >= 0 && j < t.size() && t.get(j).kind() == TokenKind.QUOTE) {
            j += dir;
        }
        if (j < 0 || j >= t.size()) {
            return null;
        }
        TokenKind k = t.get(j).kind();
        if (k == TokenKind.NUMBER || k == TokenKind.IDENT || k == TokenKind.STRING) {
            return t.get(j).text();
        }
        return null;
    }

    private static boolean hasSqlContext(List<Token> t) {
        for (Token tk : t) {
            if (tk.kind() == TokenKind.QUOTE || tk.kind() == TokenKind.STRING) {
                return true;
            }
            if (tk.kind() == TokenKind.KEYWORD && (tk.text().equals("or") || tk.text().equals("and"))) {
                return true;
            }
        }
        return false;
    }

    private static Token timeFunction(List<Token> t) {
        for (int i = 0; i < t.size(); i++) {
            Token tk = t.get(i);
            if ((tk.kind() == TokenKind.IDENT || tk.kind() == TokenKind.KEYWORD)
                    && TIME_FUNCTIONS.contains(tk.text())) {
                if (tk.text().equals("waitfor")) {
                    if (isKeyword(t, i + 1, "delay")) {
                        return tk;
                    }
                } else if (i + 1 < t.size() && t.get(i + 1).kind() == TokenKind.PUNCT
                        && t.get(i + 1).text().equals("(")) {
                    return tk;
                }
            }
        }
        return null;
    }

    private static Token informationSchema(List<Token> t) {
        for (Token tk : t) {
            if (tk.kind() == TokenKind.IDENT && tk.text().equals("information_schema")) {
                return tk;
            }
        }
        return null;
    }

    private static Token orderByNumber(List<Token> t) {
        for (int i = 0; i + 2 < t.size(); i++) {
            if (isKeyword(t, i, "order") && isKeyword(t, i + 1, "by")
                    && t.get(i + 2).kind() == TokenKind.NUMBER) {
                return t.get(i);
            }
        }
        return null;
    }

    private static Token longHexLiteral(List<Token> t) {
        for (Token tk : t) {
            if (tk.kind() == TokenKind.NUMBER && tk.text().length() >= LONG_HEX_MIN_LEN
                    && tk.text().startsWith("0x")) {
                return tk;
            }
        }
        return null;
    }

    private static Token unbalancedQuote(List<Token> t) {
        for (Token tk : t) {
            if (tk.kind() == TokenKind.QUOTE) {
                return tk;
            }
        }
        return null;
    }

    private static boolean isKeyword(List<Token> t, int i, String word) {
        return i >= 0 && i < t.size()
                && t.get(i).kind() == TokenKind.KEYWORD && t.get(i).text().equals(word);
    }
}
