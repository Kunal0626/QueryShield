package com.queryshield.proxy;

/**
 * One inspectable piece of a request: where it came from, a human name for
 * logging, the raw (still-encoded) value, and whether '+' should be read as a
 * space when normalizing it.
 *
 * <p>The {@code plusIsSpace} flag matters because the same bytes mean different
 * things in different places: in a query string {@code a+b} is "a b", but in a
 * JSON string, a header, or a path segment the '+' is a literal plus. Getting
 * this right is part of not disagreeing with the backend.
 */
public record Field(Location location, String name, String value, boolean plusIsSpace) {

    public enum Location {
        PATH, QUERY, FORM, JSON, HEADER
    }
}
