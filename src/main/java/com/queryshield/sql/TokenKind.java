package com.queryshield.sql;

/** The kinds of token {@link SqlLexer} produces from a request fragment. */
public enum TokenKind {
    /** A reserved SQL word (select, union, or, and, ...). */
    KEYWORD,
    /** A name: table/column/function identifier, or an unknown word. */
    IDENT,
    /** A terminated string literal; its {@code text} is the content, unquoted. */
    STRING,
    /** A numeric literal (including 0x.. hex runs). */
    NUMBER,
    /** An operator (=, &lt;&gt;, ||, +, ...). */
    OPERATOR,
    /** Punctuation that matters to the rules: ( ) , ; . */
    PUNCT,
    /** A line comment (-- or #) running to end of input. */
    COMMENT,
    /**
     * An unterminated / breakout quote: a quote with no matching close. In a
     * parameter value this almost always means the attacker closed the app's
     * own string literal, so it is a signal in its own right -- and the lexer
     * keeps tokenizing the characters after it as SQL, not as string content.
     */
    QUOTE
}
