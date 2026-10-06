package com.quishguard.desktop.config;

import java.io.*;
import java.nio.file.*;
import java.util.Properties;
import java.util.logging.Logger;

public class AppConfig {

    private static final Logger log = Logger.getLogger(AppConfig.class.getName());
    private static final String CONFIG_DIR  = System.getProperty("user.home") + File.separator + ".quishguard";
    private static final String CONFIG_FILE = CONFIG_DIR + File.separator + "config.properties";

    private final Properties props = new Properties();

    public void load() {
        File configFile = new File(CONFIG_FILE);

        if (!configFile.exists()) {
            log.info("No config file found — using defaults");
            setDefaults();
            save();
            return;
        }

        try (InputStream is = new FileInputStream(configFile)) {
            props.load(is);
            log.info("Config loaded from: " + CONFIG_FILE);
        } catch (IOException e) {
            log.warning("Failed to load config: " + e.getMessage());
            setDefaults();
        }
    }

    public void save() {
        try {
            Files.createDirectories(Paths.get(CONFIG_DIR));
            try (OutputStream os = new FileOutputStream(CONFIG_FILE)) {
                props.store(os, "QuishGuard Desktop Configuration");
                log.info("Config saved");
            }
        } catch (IOException e) {
            log.warning("Failed to save config: " + e.getMessage());
        }
    }

    // ─── API Keys ─────────────────────────────────────────────────────────────

    public String getVirusTotalKey() {
        return props.getProperty("api.virustotal.key", "");
    }

    public void setVirusTotalKey(String key) {
        props.setProperty("api.virustotal.key", key);
        save();
    }

    public String getGoogleSafeBrowsingKey() {
        return props.getProperty("api.gsb.key", "");
    }

    public void setGoogleSafeBrowsingKey(String key) {
        props.setProperty("api.gsb.key", key);
        save();
    }

    // ─── Scan Settings ────────────────────────────────────────────────────────

    public int getScanIntervalMs() {
        return Integer.parseInt(props.getProperty("scan.interval.ms", "800"));
    }

    public void setScanIntervalMs(int ms) {
        props.setProperty("scan.interval.ms", String.valueOf(ms));
        save();
    }

    public boolean isAutoStartEnabled() {
        return Boolean.parseBoolean(props.getProperty("app.autostart", "false"));
    }

    public void setAutoStartEnabled(boolean enabled) {
        props.setProperty("app.autostart", String.valueOf(enabled));
        save();
    }

    public boolean isNotificationsEnabled() {
        return Boolean.parseBoolean(props.getProperty("app.notifications", "true"));
    }

    public void setNotificationsEnabled(boolean enabled) {
        props.setProperty("app.notifications", String.valueOf(enabled));
        save();
    }

    // ─── Score Thresholds ─────────────────────────────────────────────────────

    public int getDangerousThreshold() {
        return Integer.parseInt(props.getProperty("score.dangerous.threshold", "70"));
    }

    public int getSuspiciousThreshold() {
        return Integer.parseInt(props.getProperty("score.suspicious.threshold", "35"));
    }

    // ─── Defaults ─────────────────────────────────────────────────────────────

    private void setDefaults() {
        props.setProperty("api.virustotal.key", "");
        props.setProperty("api.gsb.key", "");
        props.setProperty("scan.interval.ms", "800");
        props.setProperty("app.autostart", "false");
        props.setProperty("app.notifications", "true");
        props.setProperty("score.dangerous.threshold", "70");
        props.setProperty("score.suspicious.threshold", "35");
    }
}