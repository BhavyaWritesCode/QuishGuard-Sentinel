module com.quishguard.desktop {

    // JavaFX
    requires javafx.controls;
    requires javafx.fxml;
    requires javafx.swing;

    // JNA — Windows API
    requires com.sun.jna;
    requires com.sun.jna.platform;

    // HTTP client
    requires okhttp3;

    // JSON
    requires com.fasterxml.jackson.databind;

    // SQLite
    requires org.xerial.sqlitejdbc;

    // Java built-ins
    requires java.desktop;
    requires java.sql;
    requires java.logging;

    // Open packages to JavaFX for reflection
    opens com.quishguard.desktop.app      to javafx.graphics;
    opens com.quishguard.desktop.history  to javafx.graphics;
    opens com.quishguard.desktop.config   to javafx.graphics;
    opens com.quishguard.desktop.permission to javafx.graphics;
    opens com.quishguard.desktop.notification to javafx.graphics;
}