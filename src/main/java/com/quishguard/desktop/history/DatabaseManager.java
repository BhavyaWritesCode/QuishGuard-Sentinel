package com.quishguard.desktop.history;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Logger;

public class DatabaseManager {

    private static final Logger log = Logger.getLogger(DatabaseManager.class.getName());
    private static final String DB_NAME = "quishguard.db";

    private Connection connection;

    public Connection getConnection() {
        return connection;
    }

    public void initialize() {
        try {
            // Store DB in user's home directory — survives app updates
            String dbPath = System.getProperty("user.home") +
                            File.separator + ".quishguard" +
                            File.separator + DB_NAME;

            // Create .quishguard directory if it doesn't exist
            File dir = new File(System.getProperty("user.home") + File.separator + ".quishguard");
            if (!dir.exists()) dir.mkdirs();

            connection = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
            createTables();
            log.info("Database initialized at: " + dbPath);

        } catch (SQLException e) {
            throw new RuntimeException("Failed to initialize database", e);
        }
    }

    private void createTables() throws SQLException {
        Statement stmt = connection.createStatement();

        // Scan history — one row per QR code detected
        stmt.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at   INTEGER NOT NULL,
                app_name     TEXT NOT NULL,
                decoded_url  TEXT NOT NULL,
                threat_score INTEGER NOT NULL,
                verdict      TEXT NOT NULL,
                gsb_result   TEXT,
                vt_result    TEXT,
                domain_age   INTEGER,
                static_flags TEXT
            )
        """);

        // URL analysis cache — prevents duplicate API calls
        stmt.execute("""
            CREATE TABLE IF NOT EXISTS url_cache (
                url_hash       TEXT PRIMARY KEY,
                url            TEXT NOT NULL,
                gsb_result     TEXT,
                vt_result      TEXT,
                domain_age_days INTEGER,
                cached_at      INTEGER NOT NULL,
                expires_at     INTEGER NOT NULL
            )
        """);

        // Per-app permissions — allow/deny per application
        stmt.execute("""
            CREATE TABLE IF NOT EXISTS app_permissions (
                app_name    TEXT PRIMARY KEY,
                exe_path    TEXT NOT NULL,
                allowed     INTEGER NOT NULL DEFAULT 0,
                granted_at  INTEGER
            )
        """);

        stmt.close();
        log.info("Database tables ready");
    }

    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
                log.info("Database connection closed");
            }
        } catch (SQLException e) {
            log.warning("Failed to close database: " + e.getMessage());
        }
    }
}