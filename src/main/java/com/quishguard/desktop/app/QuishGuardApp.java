package com.quishguard.desktop.app;

import com.quishguard.desktop.analysis.ExternalThreatService;
import com.quishguard.desktop.analysis.StaticAnalysisService;
import com.quishguard.desktop.config.AppConfig;
import com.quishguard.desktop.config.SettingsWindow;
import com.quishguard.desktop.history.DatabaseManager;
import com.quishguard.desktop.history.HistoryWindow;
import com.quishguard.desktop.monitor.ScanOrchestrator;
import com.quishguard.desktop.monitor.ScreenCaptureService;
import com.quishguard.desktop.monitor.WindowMonitor;
import com.quishguard.desktop.permission.PermissionDialog;
import com.quishguard.desktop.permission.PermissionManager;
import com.quishguard.desktop.pipeline.QrPipelineService;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.stage.Stage;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.sql.Connection;
import java.util.logging.Logger;

public class QuishGuardApp extends Application {

    private static final Logger log = Logger.getLogger(QuishGuardApp.class.getName());

    private DatabaseManager dbManager;
    private AppConfig config;
    private ScanOrchestrator orchestrator;
    private HistoryWindow historyWindow;
    private SettingsWindow settingsWindow;
    private PermissionDialog permissionDialog;
    private TrayIcon trayIcon;

    @Override
    public void start(Stage primaryStage) {
        Platform.setImplicitExit(false);

        // ─── Init core services ───────────────────────────────────────────────
        config = new AppConfig();
        config.load();

        dbManager = new DatabaseManager();
        dbManager.initialize();

        Connection db = dbManager.getConnection();

        // ─── Init components ──────────────────────────────────────────────────
        PermissionManager permissionManager = new PermissionManager(db);
        permissionDialog  = new PermissionDialog(permissionManager);
        historyWindow     = new HistoryWindow(db);
        settingsWindow    = new SettingsWindow(config, db);

        // ─── Init scan pipeline ───────────────────────────────────────────────
        ExternalThreatService externalThreat = new ExternalThreatService(
                config.getVirusTotalKey(),
                config.getGoogleSafeBrowsingKey(),
                db
        );

        orchestrator = new ScanOrchestrator(
                new WindowMonitor(),
                new ScreenCaptureService(),
                new QrPipelineService(),
                new StaticAnalysisService(),
                externalThreat,
                permissionManager,
                db,
                config
        );

        // ─── Wire callbacks ───────────────────────────────────────────────────

        // When a QR threat is found → show tray notification + update history
        orchestrator.setOnThreatDetected(result -> {
            showThreatNotification(
                    result.appName(), result.url(),
                    result.verdict(), result.threatScore()
            );
            historyWindow.addRecord(result);
        });

        // When an unknown app is focused → show permission popup on JavaFX thread
        orchestrator.setOnPermissionRequired(window ->
                Platform.runLater(() -> permissionDialog.show(window))
        );

        // ─── Setup tray ───────────────────────────────────────────────────────
        if (!SystemTray.isSupported()) {
            log.severe("System tray not supported");
            Platform.exit();
            return;
        }

        setupTray();

        // ─── Start scanning ───────────────────────────────────────────────────
        orchestrator.start();
        log.info("QuishGuard Desktop running");
    }

    private void setupTray() {
        SystemTray tray = SystemTray.getSystemTray();

        BufferedImage icon = createTrayIcon();
        trayIcon = new TrayIcon(icon, "QuishGuard — QR Threat Monitor");
        trayIcon.setImageAutoSize(true);

        PopupMenu popup = new PopupMenu();

        MenuItem statusItem = new MenuItem("● Monitoring active");
        statusItem.setEnabled(false);

        MenuItem historyItem = new MenuItem("Scan History");
        historyItem.addActionListener(e ->
                Platform.runLater(() -> historyWindow.show()));

        MenuItem settingsItem = new MenuItem("Settings");
        settingsItem.addActionListener(e ->
                Platform.runLater(() -> settingsWindow.show()));

        MenuItem exitItem = new MenuItem("Exit QuishGuard");
        exitItem.addActionListener(e -> shutdown());

        popup.add(statusItem);
        popup.addSeparator();
        popup.add(historyItem);
        popup.add(settingsItem);
        popup.addSeparator();
        popup.add(exitItem);

        trayIcon.setPopupMenu(popup);
        trayIcon.addActionListener(e ->
                Platform.runLater(() -> historyWindow.show()));

        try {
            tray.add(trayIcon);
            log.info("Tray icon ready");
        } catch (AWTException e) {
            log.severe("Failed to add tray icon: " + e.getMessage());
        }
    }

    private void showThreatNotification(String appName, String url,
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

        String message = "App: " + appName +
                         "\nURL: " + truncate(url, 60) +
                         "\nScore: " + score + "/100";

        trayIcon.displayMessage(title, message, type);
    }

    private void shutdown() {
        log.info("Shutting down QuishGuard");
        if (orchestrator != null) orchestrator.stop();
        if (dbManager != null) dbManager.close();
        SystemTray.getSystemTray().remove(trayIcon);
        Platform.exit();
        System.exit(0);
    }

    private BufferedImage createTrayIcon() {
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
        if (orchestrator != null) orchestrator.stop();
        if (dbManager != null) dbManager.close();
    }

    public static void main(String[] args) {
        launch(args);
    }
}