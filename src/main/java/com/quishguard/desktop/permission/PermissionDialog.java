package com.quishguard.desktop.permission;

import com.quishguard.desktop.monitor.WindowMonitor.ActiveWindow;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.stage.Stage;
import javafx.stage.StageStyle;

public class PermissionDialog {

    private final PermissionManager permissionManager;

    public PermissionDialog(PermissionManager permissionManager) {
        this.permissionManager = permissionManager;
    }

    public void show(ActiveWindow window) {
        Stage stage = new Stage();
        stage.initStyle(StageStyle.UNDECORATED);
        stage.setAlwaysOnTop(true);
        stage.setTitle("QuishGuard — Permission Request");

        // ─── Header ───────────────────────────────────────────────────────────
        Label appIcon = new Label("🛡");
        appIcon.setFont(Font.font(32));

        Label title = new Label("QuishGuard wants to monitor");
        title.setFont(Font.font("System", FontWeight.BOLD, 14));
        title.setTextFill(Color.web("#1a1a1a"));

        Label appName = new Label(window.appName());
        appName.setFont(Font.font("System", FontWeight.BOLD, 18));
        appName.setTextFill(Color.web("#2E7D52"));

        Label description = new Label(
            "To detect QR code threats in this app,\n" +
            "QuishGuard needs permission to scan its window."
        );
        description.setFont(Font.font(12));
        description.setTextFill(Color.web("#555555"));
        description.setWrapText(true);

        Label privacy = new Label("✓ Only this window is scanned  ✓ No data leaves your device");
        privacy.setFont(Font.font(11));
        privacy.setTextFill(Color.web("#888888"));

        VBox header = new VBox(6, appIcon, title, appName, description, privacy);
        header.setAlignment(Pos.CENTER);
        header.setPadding(new Insets(24, 24, 16, 24));

        // ─── Buttons ──────────────────────────────────────────────────────────
        Button allowBtn = new Button("Allow Monitoring");
        allowBtn.setPrefWidth(160);
        allowBtn.setPrefHeight(38);
        allowBtn.setStyle("""
            -fx-background-color: #2E7D52;
            -fx-text-fill: white;
            -fx-font-weight: bold;
            -fx-font-size: 13px;
            -fx-background-radius: 6;
            -fx-cursor: hand;
        """);

        Button denyBtn = new Button("Don't Allow");
        denyBtn.setPrefWidth(160);
        denyBtn.setPrefHeight(38);
        denyBtn.setStyle("""
            -fx-background-color: #f0f0f0;
            -fx-text-fill: #333333;
            -fx-font-size: 13px;
            -fx-background-radius: 6;
            -fx-cursor: hand;
        """);

        allowBtn.setOnAction(e -> {
            permissionManager.grantPermission(window);
            stage.close();
        });

        denyBtn.setOnAction(e -> {
            permissionManager.denyPermission(window);
            stage.close();
        });

        HBox buttons = new HBox(12, denyBtn, allowBtn);
        buttons.setAlignment(Pos.CENTER);
        buttons.setPadding(new Insets(0, 24, 24, 24));

        // ─── Root layout ──────────────────────────────────────────────────────
        VBox root = new VBox(header, buttons);
        root.setStyle("""
            -fx-background-color: white;
            -fx-background-radius: 12;
            -fx-effect: dropshadow(gaussian, rgba(0,0,0,0.25), 20, 0, 0, 4);
        """);

        Scene scene = new Scene(root, 360, 260);
        scene.setFill(Color.TRANSPARENT);
        stage.setScene(scene);

        // Position bottom-right corner — like a system notification
        javafx.geometry.Rectangle2D screen =
            javafx.stage.Screen.getPrimary().getVisualBounds();
        stage.setX(screen.getMaxX() - 380);
        stage.setY(screen.getMaxY() - 280);

        stage.show();
    }
}