package com.quishguard.desktop.app;

import com.quishguard.desktop.config.AppConfig;
import com.quishguard.desktop.history.DatabaseManager;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.stage.Stage;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.util.logging.Logger;

public class QuishGuardApp extends Application {

    private static final Logger log = Logger.getLogger(QuishGuardApp.class.getName());

    private DatabaseManager dbManager;
    private AppConfig config;
    private TrayIcon trayIcon;

    @Override
    public void start(Stage primaryStage) {
        // Keep app alive even when no windows are open
        Platform.setImplicitExit(false);

        config = new AppConfig();
        config.load();

        dbManager = new DatabaseManager();
        dbManager.initialize();

        if (!SystemTray.isSupported()) {
            log.severe("System tray not supported on this platform");
            Platform.exit();
            return;
        }

        setupTray();
        log.info("QuishGuard Desktop started");
    }

    private void setupTray() {
        SystemTray tray = SystemTray.getSystemTray();

        // Load tray icon
        BufferedImage icon = createFallbackIcon();
        trayIcon = new TrayIcon(icon, "QuishGuard — QR Threat Monitor");
        trayIcon.setImageAutoSize(true);

        // Right-click popup menu
        PopupMenu popup = new PopupMenu();

        MenuItem historyItem = new MenuItem("Scan History");
        historyItem.addActionListener(e -> Platform.runLater(this::showHistory));

        MenuItem settingsItem = new MenuItem("Settings");
        settingsItem.addActionListener(e -> Platform.runLater(this::showSettings));

        MenuItem statusItem = new MenuItem("Status: Monitoring");
        statusItem.setEnabled(false);

        MenuItem exitItem = new MenuItem("Exit QuishGuard");
        exitItem.addActionListener(e -> shutdown());

        popup.add(statusItem);
        popup.addSeparator();
        popup.add(historyItem);
        popup.add(settingsItem);
        popup.addSeparator();
        popup.add(exitItem);

        trayIcon.setPopupMenu(popup);

        // Double-click tray icon → open history
        trayIcon.addActionListener(e -> Platform.runLater(this::showHistory));

        try {
            tray.add(trayIcon);
            log.info("Tray icon installed");
        } catch (AWTException e) {
            log.severe("Failed to add tray icon: " + e.getMessage());
        }
    }

    public void showThreatNotification(String appName, String url,
                                       String verdict, int score) {
        if (!config.isNotificationsEnabled()) return;

        String title = switch (verdict) {
            case "DANGEROUS"  -> "⚠ DANGEROUS QR Detected";
            case "SUSPICIOUS" -> "⚡ Suspicious QR Detected";
            default           -> "✓ QR Scanned — Safe";
        };

        TrayIcon.MessageType type = switch (verdict) {
            case "DANGEROUS"  -> TrayIcon.MessageType.ERROR;
            case "SUSPICIOUS" -> TrayIcon.MessageType.WARNING;
            default           -> TrayIcon.MessageType.INFO;
        };

        String message = "App: " + appName + "\nURL: " + truncate(url, 60) +
                         "\nScore: " + score + "/100";

        trayIcon.displayMessage(title, message, type);
    }

    private void showHistory() {
        // HistoryWindow — built next
        log.info("Opening history window");
    }

    private void showSettings() {
        // SettingsWindow — built later
        log.info("Opening settings window");
    }

    private void shutdown() {
        log.info("Shutting down QuishGuard");
        if (dbManager != null) dbManager.close();
        SystemTray.getSystemTray().remove(trayIcon);
        Platform.exit();
        System.exit(0);
    }

    // Fallback icon — green circle — until we add a real icon file
    private BufferedImage createFallbackIcon() {
        BufferedImage img = new BufferedImage(64, 64, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = img.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setColor(new Color(46, 125, 82));
        g.fillOval(0, 0, 64, 64);
        g.setColor(Color.WHITE);
        g.setFont(new Font("Arial", Font.BOLD, 28));
        g.drawString("Q", 18, 44);
        g.dispose();
        return img;
    }

    private String truncate(String s, int maxLen) {
        return s.length() <= maxLen ? s : s.substring(0, maxLen) + "...";
    }

    @Override
    public void stop() {
        if (dbManager != null) dbManager.close();
    }

    public static void main(String[] args) {
        launch(args);
    }

    public AppConfig getConfig() { return config; }
    public DatabaseManager getDbManager() { return dbManager; }
}