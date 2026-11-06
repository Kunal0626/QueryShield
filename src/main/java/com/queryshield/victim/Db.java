package com.queryshield.victim;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

/**
 * Loads local database settings and hands out JDBC connections for the demo app.
 *
 * <p>Why a separate file for three fields: credentials must never be committed.
 * They live in {@code victim/local.properties}, which is gitignored and is
 * created by {@code victim/setup_db.sh} with a randomly generated password. This
 * class is the single place that reads them, so there is no second copy to leak.
 */
public final class Db {

    private final String url;
    private final String user;
    private final String password;

    public Db(Path propertiesFile) {
        Properties p = new Properties();
        try (InputStream in = Files.newInputStream(propertiesFile)) {
            p.load(in);
        } catch (IOException e) {
            throw new IllegalStateException(
                    "Cannot read " + propertiesFile + "\n"
                    + "Run the one-time setup first:  bash victim/setup_db.sh", e);
        }
        this.url = require(p, "db.url");
        this.user = require(p, "db.user");
        this.password = require(p, "db.password");
    }

    private static String require(Properties p, String key) {
        String v = p.getProperty(key);
        if (v == null || v.isBlank()) {
            throw new IllegalStateException(
                    "Missing '" + key + "' in local.properties");
        }
        return v;
    }

    /** Open a fresh JDBC connection. Callers close it (try-with-resources). */
    public Connection open() throws SQLException {
        return DriverManager.getConnection(url, user, password);
    }

    /** Fail fast at startup with a clear message if the DB is unreachable. */
    public void checkReachable() {
        try (Connection c = open()) {
            if (!c.isValid(3)) {
                throw new SQLException("connection not valid");
            }
        } catch (SQLException e) {
            throw new IllegalStateException(
                    "Cannot connect to the demo database (" + url + ").\n"
                    + "Is MySQL running, and did you run: bash victim/setup_db.sh ?\n"
                    + "Driver said: " + e.getMessage(), e);
        }
    }
}
