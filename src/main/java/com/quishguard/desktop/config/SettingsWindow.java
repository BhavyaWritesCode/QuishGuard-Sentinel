package com.quishguard.desktop.config;

import com.quishguard.desktop.permission.PermissionManager;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.stage.Stage;

import java.sql.*;
import java.util.logging.Logger;

public class SettingsWindow {

    private static final Logger log = Logger.getLogger(SettingsWindow.class.getName());

    private final AppConfig config;
    private final Connection db;
    private Stage stage;

    public SettingsWindow(AppConfig config, Connection db) {
        this.config = config;
        this.db     = db;
    }

    public void show() {
        if (stage != null && stage.isShowing()) {
            stage.toFront();
            return;
        }

        stage = new Stage();
        stage.setTitle("QuishGuard — Settings");
        stage.setResizable(false);

        VBox root = new VBox(20);
        root.setPadding(new Insets(24));
        root.setStyle("-fx-background-color: #fafafa;");

        root.getChildren().addAll(
                buildApiKeysSection(),
                buildScanSection(),
                buildPermissionsSection(),
                buildSaveButton()
        );

        Scene scene = new Scene(root, 460, 520);
        stage.setScene(scene);
        stage.show();
    }

    private VBox buildApiKeysSection() {
        Label heading = sectionHeading("API Keys (Optional)");
        Label hint = new Label(
            "Add your own free API keys for enhanced threat detection.\n" +
            "Without keys, basic static analysis still runs."
        );
        hint.setFont(Font.font(11));
        hint.setTextFill(Color.web("#888888"));
        hint.setWrapText(true);

        TextField vtField = new TextField(config.getVirusTotalKey());
        vtField.setPromptText("VirusTotal API Key");
        vtField.textProperty().addListener((o, old, val) ->
                config.setVirusTotalKey(val.trim()));

        TextField gsbField = new TextField(config.getGoogleSafeBrowsingKey());
        gsbField.setPromptText("Google Safe Browsing API Key");
        gsbField.textProperty().addListener((o, old, val) ->
                config.setGoogleSafeBrowsingKey(val.trim()));

        Hyperlink vtLink = new Hyperlink("Get VirusTotal key (free)");
        vtLink.setOnAction(e -> openUrl("https://www.virustotal.com/gui/join-us"));

        Hyperlink gsbLink = new Hyperlink("Get Google Safe Browsing key (free)");
        gsbLink.setOnAction(e -> openUrl(
            "https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com"));

        return new VBox(8, heading, hint, vtField, vtLink, gsbField, gsbLink);
    }

    private VBox buildScanSection() {
        Label heading = sectionHeading("Scan Settings");

        Label intervalLabel = new Label(
                "Scan interval: " + config.getScanIntervalMs() + "ms");
        Slider intervalSlider = new Slider(400, 2000, config.getScanIntervalMs());
        intervalSlider.setMajorTickUnit(400);
        intervalSlider.setSnapToTicks(true);
        intervalSlider.valueProperty().addListener((o, old, val) -> {
            int ms = val.intValue();
            config.setScanIntervalMs(ms);
            intervalLabel.setText("Scan interval: " + ms + "ms");
        });

        CheckBox notifCheck = new CheckBox("Show threat notifications");
        notifCheck.setSelected(config.isNotificationsEnabled());
        notifCheck.selectedProperty().addListener((o, old, val) ->
                config.setNotificationsEnabled(val));

        return new VBox(8, heading, intervalLabel, intervalSlider, notifCheck);
    }

    private VBox buildPermissionsSection() {
        Label heading = sectionHeading("App Permissions");
        Label hint = new Label("Apps you have allowed or denied monitoring:");
        hint.setFont(Font.font(11));
        hint.setTextFill(Color.web("#888888"));

        VBox permList = new VBox(6);
        loadPermissions(permList);

        ScrollPane scroll = new ScrollPane(permList);
        scroll.setFitToWidth(true);
        scroll.setPrefHeight(120);
        scroll.setStyle("-fx-background-color: white;");

        return new VBox(8, heading, hint, scroll);
    }

    private void loadPermissions(VBox container) {
        try {
            PreparedStatement stmt = db.prepareStatement(
                "SELECT app_name, allowed FROM app_permissions ORDER BY app_name"
            );
            ResultSet rs = stmt.executeQuery();
            container.getChildren().clear();

            while (rs.next()) {
                String appName = rs.getString("app_name");
                boolean allowed = rs.getInt("allowed") == 1;

                Label nameLabel = new Label(appName);
                nameLabel.setPrefWidth(200);

                Label statusLabel = new Label(allowed ? "✓ Allowed" : "✗ Denied");
                statusLabel.setTextFill(allowed ?
                        Color.web("#2E7D52") : Color.web("#c62828"));

                Button revokeBtn = new Button("Reset");
                revokeBtn.setStyle("""
                    -fx-background-color: #f0f0f0;
                    -fx-font-size: 11px;
                    -fx-background-radius: 4;
                    -fx-cursor: hand;
                """);
                revokeBtn.setOnAction(e -> {
                    revokePermission(appName);
                    loadPermissions(container);
                });

                HBox row = new HBox(12, nameLabel, statusLabel,
                        new Region(), revokeBtn);
                HBox.setHgrow(row.getChildren().get(2), Priority.ALWAYS);
                row.setAlignment(Pos.CENTER_LEFT);
                row.setPadding(new Insets(4, 8, 4, 8));
                row.setStyle("-fx-background-color: white;" +
                             "-fx-border-color: #eeeeee;" +
                             "-fx-border-width: 0 0 1 0;");

                container.getChildren().add(row);
            }

            if (container.getChildren().isEmpty()) {
                container.getChildren().add(
                        new Label("No apps monitored yet."));
            }

        } catch (SQLException e) {
            log.warning("Failed to load permissions: " + e.getMessage());
        }
    }

    private void revokePermission(String appName) {
        try {
            PreparedStatement stmt = db.prepareStatement(
                "DELETE FROM app_permissions WHERE app_name = ?"
            );
            stmt.setString(1, appName);
            stmt.executeUpdate();
            log.info("Permission reset for: " + appName);
        } catch (SQLException e) {
            log.warning("Failed to revoke permission: " + e.getMessage());
        }
    }

    private HBox buildSaveButton() {
        Button closeBtn = new Button("Close");
        closeBtn.setPrefWidth(120);
        closeBtn.setPrefHeight(36);
        closeBtn.setStyle("""
            -fx-background-color: #2E7D52;
            -fx-text-fill: white;
            -fx-font-weight: bold;
            -fx-background-radius: 6;
            -fx-cursor: hand;
        """);
        closeBtn.setOnAction(e -> stage.close());

        HBox box = new HBox(closeBtn);
        box.setAlignment(Pos.CENTER_RIGHT);
        return box;
    }

    private Label sectionHeading(String text) {
        Label label = new Label(text);
        label.setFont(Font.font("System", FontWeight.BOLD, 13));
        label.setTextFill(Color.web("#1a1a1a"));
        return label;
    }

    private void openUrl(String url) {
        try {
            new ProcessBuilder("rundll32", "url.dll,FileProtocolHandler", url)
                    .start();
        } catch (Exception e) {
            log.warning("Failed to open URL: " + e.getMessage());
        }
    }
}