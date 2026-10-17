package com.quishguard.desktop.permission;

import com.quishguard.desktop.monitor.WindowMonitor.ActiveWindow;

import java.sql.*;
import java.time.Instant;
import java.util.logging.Logger;

public class PermissionManager {

    private static final Logger log = Logger.getLogger(PermissionManager.class.getName());

    private final Connection db;

    public PermissionManager(Connection db) {
        this.db = db;
    }

    public enum PermissionStatus {
        ALLOWED,      // user explicitly said yes
        DENIED,       // user explicitly said no
        NOT_ASKED     // never seen this app before
    }

    public PermissionStatus getPermission(String appName) {
        try {
            PreparedStatement stmt = db.prepareStatement(
                "SELECT allowed FROM app_permissions WHERE app_name = ?"
            );
            stmt.setString(1, appName);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                return rs.getInt("allowed") == 1
                        ? PermissionStatus.ALLOWED
                        : PermissionStatus.DENIED;
            }
            return PermissionStatus.NOT_ASKED;

        } catch (SQLException e) {
            log.warning("Permission check failed: " + e.getMessage());
            return PermissionStatus.DENIED;
        }
    }

    public void grantPermission(ActiveWindow window) {
        savePermission(window.appName(), window.exePath(), true);
        log.info("Permission GRANTED for: " + window.appName());
    }

    public void denyPermission(ActiveWindow window) {
        savePermission(window.appName(), window.exePath(), false);
        log.info("Permission DENIED for: " + window.appName());
    }

    public void revokePermission(String appName) {
        try {
            PreparedStatement stmt = db.prepareStatement(
                "DELETE FROM app_permissions WHERE app_name = ?"
            );
            stmt.setString(1, appName);
            stmt.executeUpdate();
            log.info("Permission REVOKED for: " + appName);
        } catch (SQLException e) {
            log.warning("Failed to revoke permission: " + e.getMessage());
        }
    }

    private void savePermission(String appName, String exePath, boolean allowed) {
        try {
            PreparedStatement stmt = db.prepareStatement(
                "INSERT OR REPLACE INTO app_permissions " +
                "(app_name, exe_path, allowed, granted_at) VALUES (?, ?, ?, ?)"
            );
            stmt.setString(1, appName);
            stmt.setString(2, exePath);
            stmt.setInt(3, allowed ? 1 : 0);
            stmt.setLong(4, Instant.now().getEpochSecond());
            stmt.executeUpdate();
        } catch (SQLException e) {
            log.warning("Failed to save permission: " + e.getMessage());
        }
    }
}