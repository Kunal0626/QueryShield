package com.queryshield.sql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class SqlLexerTest {

    private final SqlLexer lexer = new SqlLexer();

    private List<TokenKind> kinds(String s) {
        return lexer.lex(s).stream().map(Token::kind).toList();
    }

    @Test
    void terminatedStringIsOneToken() {
        List<Token> t = lexer.lex("'abc'");
        assertEquals(1, t.size());
        assertEquals(TokenKind.STRING, t.get(0).kind());
        assertEquals("abc", t.get(0).text());
    }

    @Test
    void doubledQuoteStaysInsideTheString() {
        List<Token> t = lexer.lex("'it''s'");
        assertEquals(1, t.size());
        assertEquals(TokenKind.STRING, t.get(0).kind());
    }

    @Test
    @DisplayName("unterminated quote becomes a breakout, and '#' after it is a comment")
    void breakoutQuoteThenComment() {
        List<Token> t = lexer.lex("admin'#");
        assertEquals(List.of(TokenKind.IDENT, TokenKind.QUOTE, TokenKind.COMMENT),
                t.stream().map(Token::kind).toList());
    }

    @Test
    @DisplayName("after a breakout quote, the rest is lexed as SQL (not string content)")
    void breakoutQuoteThenSql() {
        // o'brien -> ident, breakout quote, ident  (no comment, so it is benign)
        assertEquals(List.of(TokenKind.IDENT, TokenKind.QUOTE, TokenKind.IDENT),
                kinds("o'brien"));
    }

    @Test
    void keywordsRecognized() {
        assertEquals(List.of(TokenKind.KEYWORD, TokenKind.KEYWORD), kinds("union select"));
    }

    @Test
    @DisplayName("-- between non-spaces is two minus operators, not a comment")
    void doubleDashInsideWordIsNotComment() {
        assertEquals(List.of(TokenKind.IDENT, TokenKind.OPERATOR, TokenKind.OPERATOR, TokenKind.IDENT),
                kinds("high--five"));
    }

    @Test
    void doubleDashWithSpaceIsComment() {
        List<Token> t = lexer.lex("x -- bye");
        assertTrue(t.stream().anyMatch(tok -> tok.kind() == TokenKind.COMMENT));
    }

    @Test
    void numberEqualsNumber() {
        assertEquals(List.of(TokenKind.NUMBER, TokenKind.OPERATOR, TokenKind.NUMBER), kinds("1=1"));
    }
}
