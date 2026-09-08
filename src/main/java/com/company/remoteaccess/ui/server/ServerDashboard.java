package com.company.remoteaccess.ui.server;

import com.company.remoteaccess.MainApp;
import com.company.remoteaccess.core.configuration.AppConfig;
import com.company.remoteaccess.security.PairingManager;
import com.company.remoteaccess.server.ClientRegistry;
import com.company.remoteaccess.server.GatewayService;
import com.company.remoteaccess.server.GatewayState;
import com.company.remoteaccess.server.HealthMonitor;
import com.company.remoteaccess.server.ServerPeer;
import com.company.remoteaccess.ui.Ui;
import com.company.remoteaccess.ui.components.StatusLed;
import com.company.remoteaccess.vpn.VpnException;
import com.company.remoteaccess.vpn.VpnManager;
import com.company.remoteaccess.vpn.VpnStatus;
import javafx.animation.Animation;
import javafx.animation.Timeline;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.TextInputDialog;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;

import java.time.Duration;
import java.time.Instant;

import java.util.List;

/** Server-mode dashboard: gateway health, live statistics and device registry. */
public final class ServerDashboard extends VBox {

    private final MainApp app;
    private final GatewayService gateway;
    private final ClientRegistry registry;
    private final PairingManager pairingManager;

    private final StatusLed led = new StatusLed();
    private final Label stateLabel = new Label("STOPPED");
    private final Label subLabel = new Label("Gateway is not running.");
    private final Button fixAction = new Button();
    private final Label emptyState = new Label(
            "No devices are paired yet. Click \u201cPair a device\u201d to generate a "
                    + "one-time code for a client; the first device handshake confirms the pairing.");
    private final Label authorizedValue = new Label("0");
    private final Label onlineValue = new Label("0");
    private final Label uptimeValue = new Label("\u2014");
    private final Label rxRateValue = new Label("\u2014");
    private final Label txRateValue = new Label("\u2014");
    private final Label errorValue = new Label("\u2014");
    private final ListView<ServerPeer> devices = new ListView<>();
    private final Timeline tick = new Timeline(new javafx.animation.KeyFrame(
            javafx.util.Duration.seconds(1), e -> refresh()));

    public ServerDashboard(MainApp app) {
        this.app = app;
        this.gateway = app.gatewayService();
        this.registry = app.clientRegistry();
        this.pairingManager = app.pairingManager() != null
                ? app.pairingManager() : new PairingManager(Duration.ofMinutes(10));

        emptyState.getStyleClass().add("form-hint");
        emptyState.setWrapText(true);
        emptyState.setVisible(false);

        setSpacing(14);
        setPadding(new Insets(18));
        getChildren().addAll(statusCard(), statsRow(), emptyState, devicesCard());

        if (gateway != null) {
            gateway.addListener(new GatewayService.Listener() {
                @Override
                public void onGatewayStateChanged(GatewayState from, GatewayState to) {
                    Platform.runLater(() -> updateState(to, gateway.networkOnline()));
                }

                @Override
                public void onProgress(String step) {
                    if (step != null) {
                        Platform.runLater(() -> subLabel.setText(step));
                    }
                }
            });
        }
        if (registry != null) {
            registry.addListener(devs -> Platform.runLater(() -> devices.setItems(
                    javafx.collections.FXCollections.observableArrayList(devs))));
            devices.setItems(javafx.collections.FXCollections.observableArrayList(registry.all()));
            devices.setCellFactory(p -> new DeviceCell());
        }
        tick.setCycleCount(Animation.INDEFINITE);
        tick.play();
        refresh();
        updateState(gateway == null ? GatewayState.ERROR : gateway.state(), true);
    }

    private HBox statusCard() {
        stateLabel.getStyleClass().add("state-label");

        Button restart = new Button("Restart gateway");
        restart.getStyleClass().add("button-secondary");
        restart.setOnAction(e -> {
            if (gateway != null) {
                gateway.rebootstrap();
            }
        });

        fixAction.getStyleClass().add("button-primary");
        fixAction.setVisible(false);
        fixAction.setManaged(false);
        fixAction.setOnAction(e -> {
            Object action = fixAction.getUserData();
            if ("install".equals(action)) {
                app.installDependencies();
            } else if ("admin".equals(action)) {
                app.runAsAdministrator();
            }
        });

        Button pair = new Button("Pair a device");
        pair.getStyleClass().add("button-primary");
        pair.setOnAction(e -> {
            if (registry == null) {
                return;
            }
            String serverPub = serverPublicKey();
            AppConfig cfg = app.context().config();
            PairDeviceDialog.show(getScene().getWindow(), registry, pairingManager, cfg, serverPub);
        });

        HBox left = Ui.hbox(14, led, Ui.vbox(4, stateLabel, subLabel));
        left.setAlignment(Pos.CENTER_LEFT);
        HBox right = Ui.hbox(10, fixAction, restart, pair);
        right.setAlignment(Pos.CENTER_RIGHT);
        HBox.setHgrow(left, Priority.ALWAYS);

        HBox card = new HBox(20, left, right);
        card.getStyleClass().add("card");
        card.setPadding(new Insets(22));
        return card;
    }

    private FlowPane statsRow() {
        FlowPane row = new FlowPane(12, 12);
        row.getChildren().addAll(
                stat("Authorized devices", authorizedValue),
                stat("Online now", onlineValue),
                stat("Uptime", uptimeValue),
                stat("Rx rate", rxRateValue),
                stat("Tx rate", txRateValue),
                stat("Last error", errorValue));
        return row;
    }

    private VBox stat(String title, Label value) {
        VBox card = new VBox(6);
        card.getStyleClass().add("card");
        card.setMinWidth(148);
        Label t = Ui.label(title.toUpperCase(), "card-title");
        card.getChildren().addAll(t, value);
        value.getStyleClass().add("card-value");
        value.setStyle("-fx-font-size: 15px;");
        return card;
    }

    private VBox devicesCard() {
        Label title = Ui.label("AUTHORIZED DEVICES", "card-title");
        Label hint = Ui.label("Pair a device to generate a one-time code for the client.",
                "form-hint");
        VBox card = new VBox(10, title, hint, devices);
        card.getStyleClass().add("card");
        VBox.setVgrow(devices, Priority.ALWAYS);
        VBox.setVgrow(card, Priority.ALWAYS);
        return card;
    }

    private void refresh() {
        if (registry == null) {
            return;
        }
        int authorized = registry.countAuthorized();
        emptyState.setVisible(authorized == 0);
        HealthMonitor h = gateway == null ? null : gateway.health();
        HealthMonitor.Snapshot snap = h == null ? null : h.cached();
        authorizedValue.setText(String.valueOf(authorized));
        onlineValue.setText(snap == null ? "0" : String.valueOf(snap.onlinePeers()));
        uptimeValue.setText(snap == null ? "\u2014"
                : formatDuration(snap.uptimeSeconds()));
        rxRateValue.setText(snap == null ? "\u2014" : formatRate(snap.rxRateBps()));
        txRateValue.setText(snap == null ? "\u2014" : formatRate(snap.txRateBps()));
        errorValue.setText(snap != null && snap.lastError() != null ? snap.lastError() : "\u2014");
    }

    private void updateState(GatewayState state, boolean networkOnline) {
        stateLabel.setText(state.displayName().toUpperCase());
        switch (state) {
            case ONLINE -> {
                led.setColor(StatusLed.Color.OK);
                subLabel.setText("Gateway online. Devices can connect now.");
                setFixAction(null, null);
            }
            case RECOVERING, STARTING, STOPPING -> {
                led.setColor(StatusLed.Color.WARN);
                setFixAction(null, null);
            }
            case NETWORK_LOST -> {
                led.setColor(StatusLed.Color.WARN);
                subLabel.setText("Waiting for network connectivity\u2026");
                setFixAction(null, null);
            }
            case PERMISSION_REQUIRED -> {
                led.setColor(StatusLed.Color.ERR);
                subLabel.setText("Run the application as Administrator (or root).");
                setFixAction("Run as administrator\u2026", "admin");
            }
            case BINARIES_MISSING -> {
                led.setColor(StatusLed.Color.ERR);
                subLabel.setText("WireGuard is not installed. Install it and restart.");
                setFixAction("Install WireGuard\u2026", "install");
            }
            case ERROR -> {
                led.setColor(StatusLed.Color.ERR);
                subLabel.setText("Gateway failed. See logs in Settings.");
                setFixAction(null, null);
            }
            default -> {
                led.setColor(StatusLed.Color.IDLE);
                subLabel.setText("Gateway is stopped.");
                setFixAction(null, null);
            }
        }
    }

    private void setFixAction(String label, String action) {
        boolean show = label != null && action != null;
        fixAction.setText(show ? label : "");
        fixAction.setUserData(show ? action : null);
        fixAction.setVisible(show);
        fixAction.setManaged(show);
    }

    private String serverPublicKey() {
        VpnManager vpn = app.context().vpn();
        if (vpn == null) {
            return "";
        }
        try {
            return vpn.ensureServerKeys().publicKey();
        } catch (VpnException e) {
            return "";
        }
    }

    private static String formatRate(long bytesPerSec) {
        if (bytesPerSec <= 0) {
            return "0 B/s";
        }
        return formatBytes(bytesPerSec) + "/s";
    }

    private static String formatBytes(long b) {
        if (b >= 1_048_576) {
            return String.format("%.1f MB", b / 1_048_576.0);
        }
        if (b >= 1024) {
            return String.format("%.1f KB", b / 1024.0);
        }
        return b + " B";
    }

    private static String formatDuration(long secs) {
        if (secs <= 0) {
            return "\u2014";
        }
        long h = secs / 3600;
        long m = (secs % 3600) / 60;
        if (h > 0) {
            return h + "h " + m + "m";
        }
        return m + "m " + (secs % 60) + "s";
    }

    /** Best-effort removal of a peer key from the running tunnel. */
    private void removePeerLive(String publicKey) {
        VpnManager vpn = app.context().vpn();
        if (vpn == null || publicKey == null) {
            return;
        }
        try {
            VpnStatus st = vpn.status();
            if (st != null && st.running()) {
                vpn.adapter().removePeer(app.context().config().tunnelName(), publicKey);
            }
        } catch (VpnException ignored) {
            // revoked key may linger until the next rebootstrap regenerates peers
        }
    }

    private void renameDevice(ServerPeer d) {
        TextInputDialog dialog = new TextInputDialog(d.deviceName);
        dialog.setTitle("Rename device");
        dialog.setHeaderText(null);
        dialog.setContentText("New device name for " + d.deviceName + ":");
        dialog.showAndWait().ifPresent(newName -> {
            String clean = newName == null ? "" : newName.trim();
            if (clean.isEmpty() || clean.equals(d.deviceName)) {
                return;
            }
            try {
                registry.rename(d.deviceName, clean);
            } catch (IllegalArgumentException ex) {
                showError(ex.getMessage());
            }
        });
    }

    private void showError(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR,
                message == null ? "Operation failed." : message, ButtonType.OK);
        alert.setTitle("Cannot update device");
        alert.setHeaderText(null);
        if (getScene() != null) {
            alert.initOwner(getScene().getWindow());
        }
        alert.showAndWait();
    }

    /** Row renderer for the devices list. */
    private final class DeviceCell extends ListCell<ServerPeer> {
        @Override
        protected void updateItem(ServerPeer d, boolean empty) {
            super.updateItem(d, empty);
            if (empty || d == null) {
                setGraphic(null);
                setText(null);
                return;
            }
            VBox info = new VBox(3);
            Label name = Ui.label(d.deviceName, "card-title");
            String lastSeen = d.lastSeenAt == null || d.lastSeenAt.isBlank()
                    ? "never" : timeAgo(d.lastSeenAt);
            Label meta = Ui.label(d.vpnAddress + "  \u00b7  " + (d.publicKey.isEmpty()
                    ? "no key" : shortKey(d.publicKey))
                    + "  \u00b7  last seen " + lastSeen, "form-hint");
            info.getChildren().addAll(name, meta);

            Label statusPill = Ui.pill(d.status.name(), statusVariant(d.status));
            HBox row = new HBox(12, info, Ui.spacer(), statusPill);
            if (d.status == ServerPeer.Status.AUTHORIZED) {
                Button block = new Button("Block");
                block.getStyleClass().add("button-ghost");
                block.setOnAction(e -> {
                    registry.block(d.deviceName);
                    removePeerLive(d.publicKey);
                });
                Button revoke = new Button("Revoke");
                revoke.getStyleClass().add("button-ghost");
                revoke.setOnAction(e -> {
                    registry.revoke(d.deviceName);
                    removePeerLive(d.publicKey);
                });
                Button rename = new Button("Rename");
                rename.getStyleClass().add("button-ghost");
                rename.setOnAction(e -> renameDevice(d));
                Button repair = new Button("Re-pair");
                repair.getStyleClass().add("button-ghost");
                repair.setOnAction(e -> PairDeviceDialog.showRotate(
                        repair.getScene().getWindow(), registry, pairingManager,
                        app.context().config(), serverPublicKey(), app.context().vpn(), d));
                row.getChildren().addAll(block, revoke, rename, repair);
            } else {
                if (d.status == ServerPeer.Status.BLOCKED) {
                    Button restore = new Button("Restore");
                    restore.getStyleClass().add("button-ghost");
                    restore.setOnAction(e -> registry.unblock(d.deviceName));
                    row.getChildren().add(restore);
                }
                Button remove = new Button("Remove");
                remove.getStyleClass().add("button-ghost");
                remove.setOnAction(e -> {
                    registry.remove(d.deviceName);
                    removePeerLive(d.publicKey);
                });
                row.getChildren().add(remove);
            }
            row.setAlignment(Pos.CENTER_LEFT);
            setGraphic(row);
        }

        private static String statusVariant(ServerPeer.Status s) {
            return switch (s) {
                case AUTHORIZED -> "ok";
                case REVOKED, BLOCKED -> "err";
            };
        }

        private static String timeAgo(String iso) {
            try {
                long secs = Duration.between(Instant.parse(iso), Instant.now()).getSeconds();
                if (secs < 60) {
                    return "just now";
                }
                if (secs < 3600) {
                    return (secs / 60) + " min ago";
                }
                return (secs / 3600) + " h ago";
            } catch (Exception e) {
                return "unknown";
            }
        }

        private static String shortKey(String key) {
            return key.length() <= 12 ? key : key.substring(0, 6) + "\u2026" + key.substring(key.length() - 6);
        }
    }
}