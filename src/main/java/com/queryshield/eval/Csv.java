package com.queryshield.eval;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * A small CSV reader for the dataset files.
 *
 * <p>Just enough RFC-4180 to read what {@code build_dataset.py} writes: fields
 * may be quoted, a quoted field may contain commas, and a literal quote inside
 * a quoted field is doubled ({@code ""}). Our inputs never contain a newline,
 * so one record per line holds. Written by hand to keep the dependency list to
 * the JDBC driver only.
 */
public final class Csv {

    private Csv() {
    }

    /** Read dataset rows from a CSV with header id,input,label,category,split. */
    public static List<Row> readRows(Path path) {
        List<Row> rows = new ArrayList<>();
        try {
            List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
            for (int i = 1; i < lines.size(); i++) { // skip header
                if (lines.get(i).isEmpty()) {
                    continue;
                }
                List<String> f = parseLine(lines.get(i));
                if (f.size() != 5) {
                    throw new IllegalStateException(
                            path + " line " + (i + 1) + ": expected 5 fields, got " + f.size());
                }
                rows.add(new Row(f.get(0), f.get(1), f.get(2), f.get(3), f.get(4)));
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read " + path, e);
        }
        return rows;
    }

    /** Split one CSV record into fields, honouring quotes and doubled quotes. */
    static List<String> parseLine(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (inQuotes) {
                if (c == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        cur.append('"'); // doubled quote -> literal quote
                        i++;
                    } else {
                        inQuotes = false; // closing quote
                    }
                } else {
                    cur.append(c);
                }
            } else if (c == '"') {
                inQuotes = true;
            } else if (c == ',') {
                fields.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        fields.add(cur.toString());
        return fields;
    }
}
