package com.company.remoteaccess.ui.client;

import com.company.remoteaccess.MainApp;
import com.company.remoteaccess.client.ClientService;
import com.company.remoteaccess.client.ConnectionReport;
import com.company.remoteaccess.core.state.ConnectionState;
import com.company.remoteaccess.ui.Ui;
import com.company.remoteaccess.vpn.VpnStatus;
import javafx.animation.Animation;
import javafx.animation.Timeline;
import javafx.geometry.Insets;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.Arc;
import javafx.util.Duration;

import java.util.Optional;

/** Home-mode dashboard: one big CONNECT/DISCONNECT button beating a status ring. */
public final class ClientDashboard extends VBox {

    private final MainApp app;
    private final ClientService service;

    private final Arc ring = new Arc(58, 58, 50, 50, 90, -360);
    private final Label stateLabel = new Label("OFFLINE");
    private final Label stateSub = new Label("Set up your connection below.");
    private final Button connectButton = new Button("CONNECT");
    private final Label sessionLabel = new Label("Session: \u2014");
    private final Label latencyValue = new Label("\u2014");
    private final Label handshakeValue = new Label("\u2014");
    private final Label tunnelValue = new Label("\u2014");
    private final Label checksValue = new Label("\u2014");
    private final VBox healthBox = new VBox(6);
    private final VBox banner = new VBox(8);
    private final Timeline tick = new Timeline(new javafx.animation.KeyFrame(
            Duration.seconds(1), e -> refresh()));

    public ClientDashboard(MainApp app) {
        this.app = app;
        this.service = app.clientService();
        setSpacing(14);
        setPadding(new Insets(18));

        if (!app.context().vpnAvailable()) {
            buildWireGuardBanner();
        }

        ring.setFill(Color.TRANSPARENT);
        ring.setStrokeWidth(10);
        ring.getStyleClass().add("state-ring");
        ring.setCache(true);

        StackPane ringPane = new StackPane(ring);
        ringPane.setPrefSize(116, 116);

        stateLabel.getStyleClass().add("state-label");
        stateSub.getStyleClass().add("state-sub");
        stateSub.setWrapText(true);
        stateSub.setMaxWidth(300);

        VBox stateText = Ui.vbox(6, stateLabel, stateSub);
        stateText.setAlignment(javafx.geometry.Pos.TOP_LEFT);

        connectButton.setMinHeight(52);
        connectButton.setPrefWidth(220);
        connectButton.setOnAction(e -> toggleConnect());

        VBox actionBox = new VBox(10, connectButton, sessionLabel);
        actionBox.setAlignment(javafx.geometry.Pos.CENTER_LEFT);

        HBox mainCard = new HBox(28, ringPane, Ui.vbox(14, stateText, actionBox));
        mainCard.setAlignment(javafx.geometry.Pos.CENTER_LEFT);
        mainCard.getStyleClass().add("card");
        mainCard.setPadding(new Insets(24));

        FlowPane stats = new FlowPane(12, 12);
        stats.getChildren().addAll(
                stat("Latency", latencyValue),
                stat("Peer handshake", handshakeValue),
                stat("Tunnel", tunnelValue),
                stat("Last check", checksValue));

        healthBox.getStyleClass().add("card-flat");
        Label healthTitle = Ui.label("HEALTH CHECKS", "card-title");
        healthBox.getChildren().add(healthTitle);

        VBox keyCard = buildKeyCard();

        getChildren().addAll(banner, mainCard, stats, healthBox, keyCard);
        VBox.setVgrow(healthBox, Priority.ALWAYS);

        tick.setCycleCount(Animation.INDEFINITE);
        tick.play();
        refresh();
    }

    private void toggleConnect() {
        if (service.state() == ConnectionState.CONNECTED) {
            service.disconnect();
        } else {
            service.connect();
        }
    }

    private VBox buildKeyCard() {
        Label keyLabel = Ui.label("", "form-hint");
        keyLabel.setWrapText(true);
        Button copy = new Button("Copy public key");
        copy.getStyleClass().add("button-secondary");
        copy.setOnAction(e -> {
            String text = keyLabel.getText().trim();
            javafx.scene.input.ClipboardContent content = new javafx.scene.input.ClipboardContent();
            content.putString(text);
            javafx.scene.input.Clipboard.getSystemClipboard().setContent(content);
        });

        boolean wgOk = app.context().vpnAvailable();
        String key = "";
        if (wgOk) {
            try {
                key = app.context().vpn().ensureClientKeys().publicKey();
            } catch (Exception ignored) {
                // leave blank
            }
        }
        keyLabel.setText(wgOk && !key.isBlank()
                ? key
                : "This machine's WireGuard public key appears here once WireGuard is "
                + "installed \u2014 share it with the gateway admin to pair.");
        copy.setVisible(wgOk && !key.isBlank());
        copy.setManaged(wgOk && !key.isBlank());

        HBox row = new HBox(10,
                copy,
                Ui.label("This key is public \u2014 the gateway admin needs it to issue "
                        + "a pairing code.", "form-hint"));
        row.setAlignment(javafx.geometry.Pos.CENTER_LEFT);

        VBox card = new VBox(8,
                Ui.label("MY PUBLIC KEY (share with the gateway admin)", "card-title"),
                keyLabel, row);
        card.getStyleClass().add("card");
        return card;
    }

    private VBox stat(String title, Label value) {
        VBox card = new VBox(6);
        card.getStyleClass().add("card");
        card.setMinWidth(150);
        Label t = Ui.label(title.toUpperCase(), "card-title");
        card.getChildren().addAll(t, value);
        value.getStyleClass().add("card-value");
        value.setStyle("-fx-font-size: 16px;");
        return card;
    }

    private void refresh() {
        ConnectionState st = service.state();
        stateLabel.setText(st.label());
        connectButton.setDisable(st.isTransient());
        connectButton.setText(st == ConnectionState.CONNECTED ? "DISCONNECT" : "CONNECT");
        connectButton.getStyleClass().setAll("button",
                st == ConnectionState.CONNECTED ? "button-danger" : "button-primary");

        if (st == ConnectionState.CONNECTED) {
            stateSub.setText("Tunnel is up. " + (service.lastFailureMessage() == null
                    ? "Everything looks healthy."
                    : service.lastFailureMessage()));
        } else if (st.isTransient()) {
            stateSub.setText(st.label() + "\u2026");
        } else {
            String msg = service.lastFailureMessage();
            stateSub.setText(msg == null
                    ? "Set up your connection below."
                    : msg);
        }

        String ringColor;
        if (st == ConnectionState.CONNECTED) {
            ringColor = "-ok";
        } else if (st == ConnectionState.OFFLINE) {
            ringColor = "-surface-3";
        } else {
            ringColor = "-warn";
        }
        ring.setStyle("-fx-stroke: " + ringColor + ";");
        ring.setLength(-360);

        long secs = service.sessionDuration().getSeconds();
        if (secs > 0) {
            sessionLabel.setText("Session: " + formatDuration(secs));
        } else if (st == ConnectionState.OFFLINE) {
            sessionLabel.setText("Session: \u2014");
        }

        ConnectionReport report = service.lastReport();
        VpnStatus status = service.status();

        Optional<Long> bestLat = report == null ? Optional.empty()
                : report.checks().stream().map(ConnectionReport.Check::latencyMs)
                        .filter(l -> l > 0).min(Long::compareTo);
        latencyValue.setText(bestLat.map(l -> l + " ms").orElse("\u2014"));

        long handshake = status.peers().isEmpty() ? -1
                : status.peers().get(0).latestHandshakeSecondsAgo();
        handshakeValue.setText(handshake >= 0 ? handshake + " s ago" : "\u2014");
        tunnelValue.setText(status.running() ? "running" : "down");
        checksValue.setText(report == null ? "\u2014"
                : report.allOk() ? "all passed"
                : (report.checks().size() - report.checks().stream().filter(ConnectionReport.Check::ok).count())
                  + " failed");

        healthBox.getChildren().clear();
        healthBox.getChildren().add(Ui.label("HEALTH CHECKS", "card-title"));
        if (report == null) {
            healthBox.getChildren().add(
                    Ui.label("Run a connection to see the individual checks.", "form-hint"));
        } else {
            for (ConnectionReport.Check c : report.checks()) {
                Label row = Ui.label((c.ok() ? "\u2713  " : "\u2717  ") + c.name()
                        + (c.detail().isBlank() ? "" : "  \u00b7  " + c.detail()), "form-hint");
                row.setStyle(c.ok()
                        ? "-fx-text-fill: -ok;"
                        : "-fx-text-fill: -err;");
                healthBox.getChildren().add(row);
            }
        }
    }

    private void buildWireGuardBanner() {
        banner.getStyleClass().add("card-flat");
        Label msg = Ui.label("WireGuard was not found on this machine. "
                + "Install it from wireguard.com and choose the folder in Settings.",
                "form-hint");
        Button open = new Button("Open wireguard.com");
        open.getStyleClass().add("button-secondary");
        open.setOnAction(e -> app.getHostServices()
                .showDocument("https://www.wireguard.com/install/"));
        HBox row = new HBox(12, msg, open);
        row.setAlignment(javafx.geometry.Pos.CENTER_LEFT);
        banner.getChildren().add(row);
    }

    private static String formatDuration(long secs) {
        long h = secs / 3600;
        long m = (secs % 3600) / 60;
        long s = secs % 60;
        if (h > 0) {
            return h + "h " + m + "m";
        }
        if (m > 0) {
            return m + "m " + s + "s";
        }
        return s + "s";
    }
}