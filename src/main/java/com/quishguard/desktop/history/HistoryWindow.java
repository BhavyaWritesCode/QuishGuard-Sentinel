package com.quishguard.desktop.history;

import com.quishguard.desktop.monitor.ScanOrchestrator.ScanResult;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
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
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.logging.Logger;

public class HistoryWindow {

    private static final Logger log = Logger.getLogger(HistoryWindow.class.getName());
    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("dd MMM yyyy  HH:mm:ss")
                             .withZone(ZoneId.systemDefault());

    private final Connection db;
    private Stage stage;
    private ObservableList<ScanRecord> records;

    public HistoryWindow(Connection db) {
        this.db = db;
    }

    public void show() {
        if (stage != null && stage.isShowing()) {
            stage.toFront();
            return;
        }

        stage = new Stage();
        stage.setTitle("QuishGuard — Scan History");
        stage.setMinWidth(800);
        stage.setMinHeight(520);

        // ─── Header ───────────────────────────────────────────────────────────
        Label title = new Label("🛡  Scan History");
        title.setFont(Font.font("System", FontWeight.BOLD, 18));
        title.setTextFill(Color.web("#1a1a1a"));

        Button clearBtn = new Button("Clear History");
        clearBtn.setStyle("""
            -fx-background-color: #f5f5f5;
            -fx-text-fill: #666;
            -fx-background-radius: 6;
            -fx-cursor: hand;
        """);
        clearBtn.setOnAction(e -> clearHistory());

        HBox header = new HBox(title, new Region(), clearBtn);
        HBox.setHgrow(header.getChildren().get(1), Priority.ALWAYS);
        header.setAlignment(Pos.CENTER_LEFT);
        header.setPadding(new Insets(16, 20, 12, 20));
        header.setStyle("-fx-background-color: white; -fx-border-color: #e0e0e0; -fx-border-width: 0 0 1 0;");

        // ─── Table ────────────────────────────────────────────────────────────
        records = FXCollections.observableArrayList();
        TableView<ScanRecord> table = buildTable();
        table.setItems(records);
        VBox.setVgrow(table, Priority.ALWAYS);

        // ─── Root ─────────────────────────────────────────────────────────────
        VBox root = new VBox(header, table);
        root.setStyle("-fx-background-color: #fafafa;");

        Scene scene = new Scene(root, 860, 540);
        stage.setScene(scene);
        stage.show();

        loadHistory();
    }

    private TableView<ScanRecord> buildTable() {
        TableView<ScanRecord> table = new TableView<>();
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        table.setStyle("-fx-background-color: white;");

        TableColumn<ScanRecord, String> timeCol = new TableColumn<>("Time");
        timeCol.setCellValueFactory(d ->
            new javafx.beans.property.SimpleStringProperty(d.getValue().time()));
        timeCol.setPrefWidth(160);

        TableColumn<ScanRecord, String> appCol = new TableColumn<>("App");
        appCol.setCellValueFactory(d ->
            new javafx.beans.property.SimpleStringProperty(d.getValue().appName()));
        appCol.setPrefWidth(100);

        TableColumn<ScanRecord, String> urlCol = new TableColumn<>("URL");
        urlCol.setCellValueFactory(d ->
            new javafx.beans.property.SimpleStringProperty(d.getValue().url()));
        urlCol.setPrefWidth(300);

        TableColumn<ScanRecord, String> scoreCol = new TableColumn<>("Score");
        scoreCol.setCellValueFactory(d ->
            new javafx.beans.property.SimpleStringProperty(
                String.valueOf(d.getValue().score())));
        scoreCol.setPrefWidth(60);

        TableColumn<ScanRecord, String> verdictCol = new TableColumn<>("Verdict");
        verdictCol.setCellValueFactory(d ->
            new javafx.beans.property.SimpleStringProperty(d.getValue().verdict()));
        verdictCol.setPrefWidth(110);

        // Color-code verdict cells
        verdictCol.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(String verdict, boolean empty) {
                super.updateItem(verdict, empty);
                if (empty || verdict == null) {
                    setText(null);
                    setStyle("");
                } else {
                    setText(verdict);
                    setStyle(switch (verdict) {
                        case "DANGEROUS"  -> "-fx-text-fill: #c62828; -fx-font-weight: bold;";
                        case "SUSPICIOUS" -> "-fx-text-fill: #e65100; -fx-font-weight: bold;";
                        default           -> "-fx-text-fill: #2E7D52; -fx-font-weight: bold;";
                    });
                }
            }
        });

        TableColumn<ScanRecord, String> flagsCol = new TableColumn<>("Flags");
        flagsCol.setCellValueFactory(d ->
            new javafx.beans.property.SimpleStringProperty(d.getValue().flags()));
        flagsCol.setPrefWidth(200);

        table.getColumns().addAll(
                timeCol, appCol, urlCol, scoreCol, verdictCol, flagsCol);

        return table;
    }

    private void loadHistory() {
        try {
            PreparedStatement stmt = db.prepareStatement(
                "SELECT scanned_at, app_name, decoded_url, threat_score, " +
                "verdict, static_flags FROM scan_history ORDER BY scanned_at DESC LIMIT 200"
            );
            ResultSet rs = stmt.executeQuery();
            records.clear();

            while (rs.next()) {
                String time = FORMATTER.format(
                        Instant.ofEpochSecond(rs.getLong("scanned_at")));
                records.add(new ScanRecord(
                        time,
                        rs.getString("app_name"),
                        rs.getString("decoded_url"),
                        rs.getInt("threat_score"),
                        rs.getString("verdict"),
                        rs.getString("static_flags") == null ? "" :
                                rs.getString("static_flags")
                ));
            }
            log.info("Loaded " + records.size() + " history records");

        } catch (SQLException e) {
            log.warning("Failed to load history: " + e.getMessage());
        }
    }

    private void clearHistory() {
        try {
            db.createStatement().execute("DELETE FROM scan_history");
            records.clear();
            log.info("History cleared");
        } catch (SQLException e) {
            log.warning("Failed to clear history: " + e.getMessage());
        }
    }

    public void addRecord(ScanResult result) {
        Platform.runLater(() -> {
            String time = FORMATTER.format(Instant.now());
            records.add(0, new ScanRecord(
                    time,
                    result.appName(),
                    result.url(),
                    result.threatScore(),
                    result.verdict(),
                    String.join(", ", result.flags())
            ));
        });
    }

    public record ScanRecord(
            String time,
            String appName,
            String url,
            int score,
            String verdict,
            String flags
    ) {}
}