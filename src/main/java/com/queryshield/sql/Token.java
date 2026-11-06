package com.queryshield.sql;

/**
 * One lexed token.
 *
 * @param kind  what kind of token this is
 * @param text  its text; for {@link TokenKind#STRING} this is the unquoted
 *              content, otherwise the literal characters
 * @param start start offset in the lexed (normalized) string, inclusive
 * @param end   end offset, exclusive
 */
public record Token(TokenKind kind, String text, int start, int end) {
}
