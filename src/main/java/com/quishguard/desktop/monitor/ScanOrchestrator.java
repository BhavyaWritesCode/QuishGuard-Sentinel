package com.quishguard.desktop.monitor;

import com.quishguard.desktop.analysis.ExternalThreatService;
import com.quishguard.desktop.analysis.StaticAnalysisService;
import com.quishguard.desktop.config.AppConfig;
import com.quishguard.desktop.permission.PermissionManager;
import com.quishguard.desktop.pipeline.QrPipelineService;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.logging.Logger;
import javax.imageio.ImageIO;

public class ScanOrchestrator {

    private static final Logger log = Logger.getLogger(ScanOrchestrator.class.getName());

    private final WindowMonitor windowMonitor;
    private final ScreenCaptureService captureService;
    private final QrPipelineService qrPipeline;
    private final StaticAnalysisService staticAnalysis;
    private final ExternalThreatService externalThreat;
    private final PermissionManager permissionManager;
    private final Connection db;
    private final AppConfig config;

    // Called when a QR threat is found — wires to tray notification
    private Consumer<ScanResult> onThreatDetected;

    // Called when an unknown app is focused — wires to permission popup
    private Consumer<WindowMonitor.ActiveWindow> onPermissionRequired;

    private ScheduledExecutorService scheduler;
    private BufferedImage lastScreenshot;
    private String lastAppName = "";

    // URLs already scanned in this session — avoids rescanning same URL repeatedly
    private final Set<String> scannedUrls = new HashSet<>();

    public ScanOrchestrator(WindowMonitor windowMonitor,
                            ScreenCaptureService captureService,
                            QrPipelineService qrPipeline,
                            StaticAnalysisService staticAnalysis,
                            ExternalThreatService externalThreat,
                            PermissionManager permissionManager,
                            Connection db,
                            AppConfig config) {
        this.windowMonitor   = windowMonitor;
        this.captureService  = captureService;
        this.qrPipeline      = qrPipeline;
        this.staticAnalysis  = staticAnalysis;
        this.externalThreat  = externalThreat;
        this.permissionManager = permissionManager;
        this.db              = db;
        this.config          = config;
    }

    public void setOnThreatDetected(Consumer<ScanResult> handler) {
        this.onThreatDetected = handler;
    }

    public void setOnPermissionRequired(Consumer<WindowMonitor.ActiveWindow> handler) {
        this.onPermissionRequired = handler;
    }

    public void start() {
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "scan-loop");
            t.setDaemon(true);
            return t;
        });

        scheduler.scheduleAtFixedRate(
                this::scanLoop,
                1000,
                config.getScanIntervalMs(),
                TimeUnit.MILLISECONDS
        );
        log.info("Scan loop started — interval: " + config.getScanIntervalMs() + "ms");
    }

    public void stop() {
        if (scheduler != null) {
            scheduler.shutdownNow();
            log.info("Scan loop stopped");
        }
    }

    private void scanLoop() {
        try {
            WindowMonitor.ActiveWindow window = windowMonitor.getActiveWindow();
            if (window == null) return;

            // Check permission for this app
            PermissionManager.PermissionStatus status =
                    permissionManager.getPermission(window.appName());

            if (status == PermissionManager.PermissionStatus.DENIED) return;

            if (status == PermissionManager.PermissionStatus.NOT_ASKED) {
                // Only ask once per app per session
                if (!window.appName().equals(lastAppName)) {
                    lastAppName = window.appName();
                    if (onPermissionRequired != null) {
                        onPermissionRequired.accept(window);
                    }
                }
                return;
            }

            // Capture screenshot of permitted window
            BufferedImage screenshot = captureService.capture(window.bounds());
            if (screenshot == null) return;

            // Skip if screen hasn't changed
            if (!captureService.hasChanged(lastScreenshot, screenshot)) return;
            lastScreenshot = screenshot;

            // Run QR detection
            List<String> urls = qrPipeline.extractUrls(toInputStream(screenshot));
            if (urls.isEmpty()) return;

            // Analyze each new URL found
            for (String url : urls) {
                if (scannedUrls.contains(url)) continue;
                scannedUrls.add(url);

                analyzeAndStore(url, window.appName());
            }

        } catch (Exception e) {
            log.warning("Scan loop error: " + e.getMessage());
        }
    }

    private void analyzeAndStore(String url, String appName) {
        try {
            List<String> flags = staticAnalysis.analyze(url);
            int score = staticAnalysis.computeScore(flags);

            ExternalThreatService.ExternalThreatResult external =
                    externalThreat.analyze(url);

            // Boost score from external results
            if ("MALICIOUS".equals(external.gsbResult())) score = Math.min(100, score + 50);
            if (external.domainAgeDays() != -1 && external.domainAgeDays() < 30) {
                score = Math.min(100, score + 25);
            }

            String verdict = score >= config.getDangerousThreshold()  ? "DANGEROUS"  :
                             score >= config.getSuspiciousThreshold() ? "SUSPICIOUS" : "SAFE";

            // Save to SQLite
            saveToHistory(appName, url, score, verdict,
                    external.gsbResult(), external.virusTotalSummary(),
                    external.domainAgeDays(), flags);

            ScanResult result = new ScanResult(
                    appName, url, score, verdict,
                    external.gsbResult(), external.virusTotalSummary(),
                    external.domainAgeDays(), flags
            );

            log.info("QR scanned — " + verdict + " (" + score + ") — " + url);

            if (onThreatDetected != null) {
                onThreatDetected.accept(result);
            }

        } catch (Exception e) {
            log.warning("Analysis failed for URL: " + url + " — " + e.getMessage());
        }
    }

    private void saveToHistory(String appName, String url, int score,
                               String verdict, String gsb, String vt,
                               int domainAge, List<String> flags) {
        try {
            PreparedStatement stmt = db.prepareStatement(
                "INSERT INTO scan_history " +
                "(scanned_at, app_name, decoded_url, threat_score, verdict, " +
                "gsb_result, vt_result, domain_age, static_flags) " +
                "VALUES (?,?,?,?,?,?,?,?,?)"
            );
            stmt.setLong(1, Instant.now().getEpochSecond());
            stmt.setString(2, appName);
            stmt.setString(3, url);
            stmt.setInt(4, score);
            stmt.setString(5, verdict);
            stmt.setString(6, gsb);
            stmt.setString(7, vt);
            stmt.setInt(8, domainAge);
            stmt.setString(9, String.join(",", flags));
            stmt.executeUpdate();
        } catch (SQLException e) {
            log.warning("Failed to save scan to history: " + e.getMessage());
        }
    }

    private java.io.InputStream toInputStream(BufferedImage image) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, "PNG", baos);
        return new ByteArrayInputStream(baos.toByteArray());
    }

    public record ScanResult(
            String appName,
            String url,
            int threatScore,
            String verdict,
            String gsbResult,
            String virusTotalSummary,
            int domainAgeDays,
            List<String> flags
    ) {}
}