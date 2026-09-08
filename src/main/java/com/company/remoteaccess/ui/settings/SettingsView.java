package com.company.remoteaccess.ui.settings;

import com.company.remoteaccess.BuildInfo;
import com.company.remoteaccess.MainApp;
import com.company.remoteaccess.core.configuration.AppConfig;
import com.company.remoteaccess.core.state.Role;
import com.company.remoteaccess.diagnostics.Diagnostics;
import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogEntry;
import com.company.remoteaccess.platform.RequirementChecker;
import com.company.remoteaccess.security.ConfigIntegrity;
import com.company.remoteaccess.security.Secrets;
import com.company.remoteaccess.startup.StartupManager;
import com.company.remoteaccess.ui.Ui;
import javafx.animation.Animation;
import javafx.animation.Timeline;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.util.Duration;

import java.io.File;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/** Settings: general, VPN, routing, security/startup, advanced and live logs. */
public final class SettingsView extends VBox {

    private final MainApp app;
    private final StartupManager startup;
    private final TabPane tabs = new TabPane();
    private final Label saveFeedback = Ui.label("", "pill-ok");
    private final TextArea logArea = new TextArea();

    private final TextField deviceName = new TextField();
    private final TextField gatewayName = new TextField();
    private final ComboBox<String> theme = new ComboBox<>();
    private final TextField wgDir = new TextField();
    private final TextField tunnelName = new TextField();
    private final TextField mtu = new TextField();
    private final ComboBox<String> routingMode = new ComboBox<>();
    private final TextArea extraRoutes = new TextArea();
    private final TextField dns = new TextField();
    private final CheckBox autoReconnect = new CheckBox("Reconnect automatically");
    private final CheckBox autoConnect = new CheckBox("Connect automatically when the application starts");
    private final TextField maxRetries = new TextField();
    private final TextField backoff = new TextField();
    private final TextField startPort = new TextField();

    private final Timeline logTick = new Timeline(new javafx.animation.KeyFrame(
            Duration.seconds(2), e -> refreshLogs()));

    private volatile Diagnostics.Report lastReport;

    public SettingsView(MainApp app) {
        this.app = app;
        this.startup = new StartupManager(app.context().runner);
        setSpacing(12);
        setPadding(new Insets(18));

        tabs.getStyleClass().add("card");
        tabs.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);
        tabs.getTabs().addAll(
                generalTab(), vpnTab(), routingTab(), securityTab(), advancedTab(), logsTab(),
                auditTab(), supportTab());
        VBox.setVgrow(tabs, Priority.ALWAYS);

        HBox actions = new HBox(10, saveButton(), Ui.spacer(), saveFeedback);
        actions.setAlignment(Pos.CENTER_RIGHT);

        getChildren().addAll(Ui.label("SETTINGS", "app-title"), tabs, actions);
        logTick.setCycleCount(Animation.INDEFINITE);
        logTick.play();
    }

    private Button saveButton() {
        Button save = new Button("Save settings");
        save.getStyleClass().add("button-primary");
        save.setOnAction(e -> saveAll());
        return save;
    }

    // ------------------------------------------------------------------

    private Tab generalTab() {
        AppConfig cfg = app.context().config();
        deviceName.setText(cfg.clientDeviceName().isBlank()
                ? System.getProperty("user.name", "my-computer") : cfg.clientDeviceName());
        gatewayName.setText(cfg.serverName());
        if (cfg.mode() == com.company.remoteaccess.core.state.Role.SERVER) {
            gatewayName.setDisable(false);
        } else {
            gatewayName.setEditable(false);
        }
        theme.getItems().addAll("dark", "light");
        theme.setValue(cfg.theme());

        CheckBox startWithOs = new CheckBox("Start with the operating system");
        try {
            startWithOs.setSelected(startup.isEnabled());
        } catch (Exception ignored) {
            // read failure: leave unselected
        }
        startWithOs.selectedProperty().addListener((o, a, b) -> startup.apply(b));

        var box = form(
                Ui.label("DEVICE NAME", "form-label"), deviceName,
                fieldRow("GATEWAY NAME (DISPLAY)", gatewayName),
                Ui.label("THEME", "form-label"), theme,
                fieldRow("LAUNCH ON LOGIN", startWithOs));

        Role role = app.role();
        Label roleNote = Ui.label(
                "This application runs "
                        + (role == Role.SERVER ? "as the GATEWAY (SERVER)" : "as a WORKSTATION (CLIENT)")
                        + ". Fields that only belong to the other role are disabled \u2014 "
                        + "everything here is still the same app, just showing the fields "
                        + "that matter for this computer's job.",
                "pill-warn");
        roleNote.setWrapText(true);

        Button elevate = new Button("Enable administrator mode\u2026");
        elevate.getStyleClass().add("button-primary");
        elevate.setOnAction(e -> app.runAsAdministrator());
        boolean elevated = com.company.remoteaccess.platform.Elevation.isElevated();
        if (elevated) {
            elevate.setDisable(true);
            elevate.setText("Administrator mode is already active");
        }
        Label permHint = Ui.label(
                "Administrator privileges are required for: automatic WireGuard install, "
                        + "FULL_TUNNEL routing, NAT and firewall rules, and creating the "
                        + "tunnel interface. Click the button once and approve the UAC prompt.",
                "form-hint");
        permHint.setWrapText(true);

        return tab("General", new VBox(12, box, roleNote, elevate, permHint));
    }

    private Tab vpnTab() {
        AppConfig cfg = app.context().config();
        wgDir.setText(cfg.wgBinaryDir());
        tunnelName.setText(cfg.tunnelName());
        mtu.setText(String.valueOf(cfg.mtu()));
        startPort.setText(String.valueOf(cfg.listenPort()));
        Label serverOnly = null;
        if (app.role() != Role.SERVER) {
            startPort.setDisable(true);
            startPort.setPromptText("This is a gateway (server) setting.");
            serverOnly = Ui.label("Listen port belongs to the gateway. This device runs "
                    + "as a CLIENT, so it is disabled here \u2014 it is set on the server "
                    + "and distributed through the pairing code.", "form-hint");
            serverOnly.setWrapText(true);
        }

        var box = form(
                Ui.label("WIREGUARD BINARY FOLDER", "form-label"), wgDir,
                fieldRow("TUNNEL NAME (ADMIN ONLY)", tunnelName),
                fieldRow("MTU", mtu),
                fieldRow("SERVER LISTEN PORT (UDP)", startPort),
                Ui.label("Leave the binary folder empty to search PATH and the default "
                        + "install locations automatically.", "form-hint"));
        return tab("VPN", serverOnly == null ? box : new VBox(12, box, serverOnly));
    }

    private Tab routingTab() {
        AppConfig cfg = app.context().config();
        routingMode.getItems().addAll("SPLIT_TUNNEL", "FULL_TUNNEL");
        routingMode.setValue(cfg.routingMode());
        dns.setText(cfg.clientDnsOverride());
        extraRoutes.setText(String.join(", ", cfg.extraRoutes()));
        extraRoutes.setPrefRowCount(4);

        var box = form(
                Ui.label("ROUTING MODE", "form-label"), routingMode,
                fieldRow("EXTRA ROUTES (CIDR, comma-separated)", extraRoutes),
                fieldRow("DNS OVERRIDE (CLIENT)", dns),
                Ui.label("FULL_TUNNEL requires administrator privileges and sends all "
                        + "station traffic through the company gateway.", "form-hint"));
        return tab("Routing", box);
    }

    private Tab securityTab() {
        AppConfig cfg = app.context().config();
        autoReconnect.setSelected(cfg.autoReconnect());
        autoConnect.setSelected(cfg.connectOnAppStart());
        startPort.setText(String.valueOf(cfg.listenPort()));
        maxRetries.setText(String.valueOf(cfg.maxRetries()));
        backoff.setText(String.valueOf(cfg.backoffBaseMs()));

        var box = form(
                fieldRow("RECONNECTION", autoReconnect),
                fieldRow("AUTO CONNECT ON STARTUP", autoConnect),
                fieldRow("MAX RETRIES", maxRetries),
                fieldRow("BACKOFF BASE (ms)", backoff));
        return tab("Security", box);
    }

    private Tab advancedTab() {
        Button reset = new Button("Reset configuration");
        reset.getStyleClass().add("button-danger");
        reset.setOnAction(e -> {
            try {
                java.nio.file.Files.deleteIfExists(app.context().configFile);
                app.context().updateConfig(AppConfig.create());
            } catch (Exception ex) {
                saveFeedback.setText("Reset failed: " + ex.getMessage());
                saveFeedback.getStyleClass().setAll("pill", "pill-err");
                saveFeedback.setVisible(true);
                return;
            }
            saveFeedback.setText("Configuration reset. The first-run wizard will ask"
                    + " to choose CLIENT or SERVER on the next start.");
            saveFeedback.getStyleClass().setAll("pill", "pill-warn");
            saveFeedback.setVisible(true);
        });

        Button scratch = new Button("Start from scratch\u2026");
        scratch.getStyleClass().add("button-danger");
        scratch.setOnAction(e -> {
            ButtonType cancel = new ButtonType("Cancel", ButtonBar.ButtonData.CANCEL_CLOSE);
            ButtonType wipe = new ButtonType("Wipe and start over", ButtonBar.ButtonData.OK_DONE);
            javafx.scene.control.Alert confirm = new javafx.scene.control.Alert(
                    javafx.scene.control.Alert.AlertType.CONFIRMATION);
            confirm.setTitle("Start from scratch");
            confirm.setHeaderText("Re-run the first-run setup and choose a role again");
            confirm.setContentText("This clears the configuration, your WireGuard keys, "
                    + "paired devices and audit data on this computer. The application "
                    + "will immediately ask you to choose CLIENT or SERVER and hand you "
                    + "a fresh start.");
            confirm.getButtonTypes().setAll(wipe, cancel);
            confirm.showAndWait().ifPresent(b -> {
                if (b == wipe) {
                    app.resetToFirstRun();
                }
            });
        });

        var box = new VBox(12,
                Ui.label("DANGER ZONE", "card-title"),
                Ui.label("Reset configuration keeps your keys and returns to the setup "
                        + "wizard on the next start. Start from scratch clears everything "
                        + "(configuration, keys, paired devices, audit data) and re-runs "
                        + "the first-run role choice immediately.", "form-hint"),
                reset,
                scratch);
        return tab("Advanced", box);
    }

    private Tab logsTab() {
        logArea.setEditable(false);
        logArea.getStyleClass().add("log-view");
        logArea.setPrefRowCount(18);
        refreshLogs();
        var box = new VBox(8, logArea);
        return tab("Logs", box);
    }

    private Tab auditTab() {
        Label heading = Ui.label("SECURITY AUDIT", "card-title");
        Label hint = Ui.label("Tamper-evident event trail for pairing, device changes and "
                + "gateway lifecycle. Details are stored only as hashes \u2014 no secrets "
                + "appear here. Written to data/audit.log.", "form-hint");

        Label chain = Ui.label("", "pill");
        TextArea auditArea = new TextArea();
        auditArea.setEditable(false);
        auditArea.getStyleClass().add("log-view");
        auditArea.setPrefRowCount(14);

        Button refresh = new Button("Refresh");
        refresh.getStyleClass().add("button-secondary");
        Button copy = new Button("Copy to clipboard");
        copy.getStyleClass().add("button-ghost");
        copy.setOnAction(e -> copyAudit(auditArea));

        Runnable reload = () -> {
            Path auditFile = app.context().dataDir.resolve("audit.log");
            var entries = com.company.remoteaccess.security.AuditView.read(auditFile, 300);
            auditArea.setText(entries.isEmpty()
                    ? "No audit events recorded yet."
                    : com.company.remoteaccess.security.AuditView.render(entries));
            boolean verified = com.company.remoteaccess.security.AuditView.verified(auditFile);
            chain.setText(verified ? "hash chain verified" : "TAMPERING DETECTED");
            chain.getStyleClass().setAll("pill", verified ? "pill" : "pill-err");
            if (verified) {
                chain.getStyleClass().add("pill-ok");
            }
            copy.setDisable(entries.isEmpty());
        };
        refresh.setOnAction(e -> reload.run());
        reload.run();

        HBox actions = Ui.hbox(8, refresh, copy);
        var box = new VBox(8, heading, hint, chain, auditArea, actions);
        return tab("Audit", box);
    }

    private void copyAudit(TextArea auditArea) {
        if (auditArea.getText().isEmpty()) {
            return;
        }
        ClipboardContent content = new ClipboardContent();
        content.putString(auditArea.getText());
        Clipboard.getSystemClipboard().setContent(content);
    }

    private boolean encryptionActive() {
        return app.context().configManager.exists()
                && java.nio.file.Files.exists(app.context().configFile)
                && com.company.remoteaccess.security.ConfigCipher.isEncrypted(
                readFirstChars(app.context().configFile, 32));
    }

    private static String readFirstChars(Path file, int max) {
        try {
            String s = java.nio.file.Files.readString(file, java.nio.charset.StandardCharsets.UTF_8);
            return s.length() <= max ? s : s.substring(0, max);
        } catch (Exception e) {
            return "";
        }
    }

    private Tab supportTab() {
        Label about = Ui.label("ABOUT", "card-title");
        Label version = Ui.label("App version  " + BuildInfo.versionLabel(), "form-hint");
        if (!BuildInfo.vendor().isBlank()) {
            version = Ui.label("App version  " + BuildInfo.versionLabel() + "  \u00b7  "
                    + BuildInfo.vendor(), "form-hint");
        }
        Label javaLabel = Ui.label("Java  " + System.getProperty("java.version", "unknown"), "form-hint");
        Label os = Ui.label("OS  " + System.getProperty("os.name", "unknown") + " / "
                + System.getProperty("os.arch", "unknown"), "form-hint");
        Label user = Ui.label("User  " + System.getProperty("user.name", "unknown"), "form-hint");
        Label dataDir = fieldText("Data directory  " + app.context().baseDir.toAbsolutePath());

        boolean sidecar = java.nio.file.Files.exists(
                ConfigIntegrity.sidecarFor(app.context().configFile));
        Label integrity = Ui.label("Config integrity  "
                + (sidecar ? "active (HMAC sidecar present)" : "legacy (sidecar writes on next save)"),
                "form-hint");
        Label atRest = fieldText("Config encryption at rest  "
                + (encryptionActive() ? "active (AES-256-GCM, key in credential store)"
                : "disabled (legacy plaintext)"));

        TextArea reportArea = new TextArea();
        reportArea.setEditable(false);
        reportArea.getStyleClass().add("log-view");
        reportArea.setPrefRowCount(14);

        Button generate = new Button("Generate report");
        generate.getStyleClass().add("button-primary");
        generate.setOnAction(e -> refreshReport(reportArea));

        Button save = new Button("Save report\u2026");
        save.getStyleClass().add("button-secondary");
        save.setDisable(true);
        save.setOnAction(e -> saveReport());

        Button copy = new Button("Copy to clipboard");
        copy.getStyleClass().add("button-ghost");
        copy.setDisable(true);
        copy.setOnAction(e -> copyReport(reportArea));

        HBox actions = Ui.hbox(8, generate, save, copy);
        var box = new VBox(8,
                about,
                version, javaLabel, os, user, dataDir, integrity, atRest,
                Ui.label("SUPPORT REPORT", "card-title"),
                Ui.label("A redacted system snapshot for support tickets. No private keys, "
                        + "tokens or pairing payloads are included.", "form-hint"),
                reportArea,
                actions);
        return tab("Support", box);
    }

    private void refreshReport(TextArea reportArea) {
        try {
            AppConfig cfg = app.context().config();
            boolean server = cfg.mode() == com.company.remoteaccess.core.state.Role.SERVER;
            var requirements = RequirementChecker.survey(app.context().runner, cfg.wgBinaryDir(),
                    server, app.context().configManager.exists());
            boolean startup = new StartupManager(app.context().runner).isEnabled();
            Diagnostics.Report report = Diagnostics.gather(app.context(),
                    app.context().network.isOnline(), requirements, startup);
            lastReport = report;
            reportArea.setText(Secrets.redact(report.render()));
            for (javafx.scene.Node n : ((VBox) reportArea.getParent()).getChildren()) {
                if (n instanceof Button) {
                    ((Button) n).setDisable(false);
                }
            }
        } catch (Exception e) {
            reportArea.setText("Could not generate the report: " + e.getMessage());
        }
    }

    private void saveReport() {
        if (lastReport == null) {
            return;
        }
        FileChooser fc = new FileChooser();
        fc.setTitle("Save support report");
        fc.setInitialFileName("company-remote-diagnostics-"
                + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")) + ".txt");
        File target = fc.showSaveDialog(getScene() == null ? null : getScene().getWindow());
        if (target == null) {
            return;
        }
        try {
            Diagnostics.write(target.toPath(), lastReport);
            saveFeedback.setText("Report saved to " + target.getAbsolutePath());
            saveFeedback.getStyleClass().setAll("pill", "pill-ok");
            saveFeedback.setVisible(true);
        } catch (Exception e) {
            saveFeedback.setText("Save failed: " + e.getMessage());
            saveFeedback.getStyleClass().setAll("pill", "pill-err");
            saveFeedback.setVisible(true);
        }
    }

    private void copyReport(TextArea reportArea) {
        if (reportArea.getText().isEmpty()) {
            return;
        }
        ClipboardContent content = new ClipboardContent();
        content.putString(reportArea.getText());
        Clipboard.getSystemClipboard().setContent(content);
    }

    private static Label fieldText(String text) {
        Label l = Ui.label(text, "form-hint");
        l.setWrapText(true);
        return l;
    }

    // ------------------------------------------------------------------

    private void saveAll() {
        AppConfig cfg = app.context().config();
        try {
            AppConfig next = cfg
                    .with("app.theme", theme.getValue() == null ? "dark" : theme.getValue())
                    .with("client.deviceName", deviceName.getText().isBlank()
                            ? System.getProperty("user.name", "my-computer") : deviceName.getText().trim())
                    .with("server.name", gatewayName.getText().isBlank()
                            ? "Company-Gateway" : gatewayName.getText().trim())
                    .with("vpn.binaryDir", wgDir.getText().trim())
                    .with("vpn.tunnelName", tunnelName.getText().isBlank()
                            ? "company0" : tunnelName.getText().trim())
                    .with("server.listenPort", intOr(startPort.getText(), cfg.listenPort()))
                    .with("routing.mode", routingMode.getValue() == null
                            ? "SPLIT_TUNNEL" : routingMode.getValue())
                    .with("routing.routes", parseRoutes(extraRoutes.getText()))
                    .with("client.dnsOverride", dns.getText().trim())
                    .with("security.autoReconnect", autoReconnect.isSelected())
                    .with("security.connectOnAppStart", autoConnect.isSelected())
                    .with("security.maxRetries", intOr(maxRetries.getText(), cfg.maxRetries()))
                    .with("security.backoffBaseMs", intOr(backoff.getText(), cfg.backoffBaseMs()))
                    .with("vpn.mtu", intOr(mtu.getText(), cfg.mtu()));
            app.context().updateConfig(next);
            app.applyTheme(next.theme());
            saveFeedback.setText("Saved.");
            saveFeedback.getStyleClass().setAll("pill", "pill-ok");
            saveFeedback.setVisible(true);
        } catch (Exception e) {
            saveFeedback.setText("Save failed: " + e.getMessage());
            saveFeedback.getStyleClass().setAll("pill", "pill-err");
            saveFeedback.setVisible(true);
        }
    }

    private void refreshLogs() {
        List<LogEntry> entries = AppLogger.getLogger().snapshot();
        if (entries.isEmpty()) {
            return;
        }
        int start = Math.max(0, entries.size() - 200);
        StringBuilder sb = new StringBuilder();
        for (int i = start; i < entries.size(); i++) {
            sb.append(entries.get(i)).append('\n');
        }
        logArea.setText(sb.toString());
        logArea.setScrollTop(Double.MAX_VALUE);
    }

    private static HBox fieldRow(String label, javafx.scene.Node field) {
        Label l = Ui.label(label, "form-label");
        l.setMinWidth(210);
        HBox row = new HBox(12, l, field);
        row.setAlignment(Pos.CENTER_LEFT);
        HBox.setHgrow(field, Priority.ALWAYS);
        return row;
    }

    private static VBox form(javafx.scene.Node... nodes) {
        VBox v = new VBox(12);
        v.getChildren().addAll(nodes);
        v.setPadding(new Insets(4, 8, 8, 8));
        return v;
    }

    private static Tab tab(String title, javafx.scene.Node box) {
        Tab t = new Tab(title);
        ScrollPane sp = new ScrollPane(box);
        sp.setFitToWidth(true);
        t.setContent(sp);
        return t;
    }

    private static int intOr(String text, int dflt) {
        try {
            return Integer.parseInt(text.trim());
        } catch (Exception e) {
            return dflt;
        }
    }

    private static List<String> parseRoutes(String text) {
        java.util.ArrayList<String> out = new java.util.ArrayList<>();
        for (String part : text.split("[,\\s\\n]+")) {
            if (!part.isBlank()) {
                out.add(part.trim());
            }
        }
        return out;
    }
}