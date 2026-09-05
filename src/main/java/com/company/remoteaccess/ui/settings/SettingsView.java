package com.company.remoteaccess.ui.settings;

import com.company.remoteaccess.MainApp;
import com.company.remoteaccess.core.configuration.AppConfig;
import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogEntry;
import com.company.remoteaccess.startup.StartupManager;
import com.company.remoteaccess.ui.Ui;
import javafx.animation.Animation;
import javafx.animation.Timeline;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.util.Duration;

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
    private final TextField maxRetries = new TextField();
    private final TextField backoff = new TextField();
    private final TextField startPort = new TextField();

    private final Timeline logTick = new Timeline(new javafx.animation.KeyFrame(
            Duration.seconds(2), e -> refreshLogs()));

    public SettingsView(MainApp app) {
        this.app = app;
        this.startup = new StartupManager(app.context().runner);
        setSpacing(12);
        setPadding(new Insets(18));

        tabs.getStyleClass().add("card");
        tabs.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);
        tabs.getTabs().addAll(
                generalTab(), vpnTab(), routingTab(), securityTab(), advancedTab(), logsTab());
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
        return tab("General", box);
    }

    private Tab vpnTab() {
        AppConfig cfg = app.context().config();
        wgDir.setText(cfg.wgBinaryDir());
        tunnelName.setText(cfg.tunnelName());
        mtu.setText(String.valueOf(cfg.mtu()));
        startPort.setText(String.valueOf(cfg.listenPort()));

        var box = form(
                Ui.label("WIREGUARD BINARY FOLDER", "form-label"), wgDir,
                fieldRow("TUNNEL NAME (ADMIN ONLY)", tunnelName),
                fieldRow("MTU", mtu),
                fieldRow("SERVER LISTEN PORT (UDP)", startPort),
                Ui.label("Leave the binary folder empty to search PATH and the default "
                        + "install locations automatically.", "form-hint"));
        return tab("VPN", box);
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
        startPort.setText(String.valueOf(cfg.listenPort()));
        maxRetries.setText(String.valueOf(cfg.maxRetries()));
        backoff.setText(String.valueOf(cfg.backoffBaseMs()));

        var box = form(
                fieldRow("RECONNECTION", autoReconnect),
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
            saveFeedback.setText("Configuration reset. Restart the application.");
            saveFeedback.getStyleClass().setAll("pill", "pill-warn");
            saveFeedback.setVisible(true);
        });

        var box = new VBox(12,
                Ui.label("DANGER ZONE", "card-title"),
                Ui.label("Clears the local configuration and returns to the setup "
                        + "wizard on the next start. Credentials and keys are kept.",
                        "form-hint"),
                reset);
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