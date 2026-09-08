package com.company.remoteaccess.ui.setup;

import com.company.remoteaccess.core.configuration.AppConfig;
import com.company.remoteaccess.networking.IpHelpers;
import com.company.remoteaccess.ui.Ui;
import com.company.remoteaccess.vpn.KeyManager;
import javafx.animation.Animation;
import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.geometry.Insets;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TextField;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.util.Duration;

/**
 * Server setup: gateway discovery, VPN subnet and company LAN details. The whole
 * page scrolls so every field stays reachable, and the gateway's (public) WireGuard
 * key is shown with a one-click copy. Writes the config with mode=SERVER so the
 * application runs as a gateway.
 */
final class ServerSetupPage extends VBox {

    ServerSetupPage(SetupWizard w) {
        w.setTitle("Configure the company gateway", "");
        w.setBack(w::showWelcome, true);

        TextField name = new TextField(w.app().context().config().serverName());
        name.setPrefColumnCount(20);
        TextField port = new TextField(String.valueOf(w.app().context().config().listenPort()));
        TextField vpnSubnet = new TextField(w.app().context().config().vpnSubnet());
        vpnSubnet.setPromptText("10.50.0.0/24");
        TextField lanCidr = new TextField(w.app().context().config().lanCidr());
        lanCidr.setPromptText("192.168.1.0/24");
        TextField endpoint = new TextField(w.app().context().config().serverHost());
        endpoint.setPromptText("e.g. gateway.example.com or 203.0.113.10");
        TextField lanIface = new TextField(w.app().context().config().lanInterface());
        lanIface.setPromptText("e.g. eth0 / Ethernet (optional)");

        Label error = Ui.label("", "pill-err");
        error.setVisible(false);

        VBox wgBox = new VBox(8,
                Ui.label("WireGuard is not installed. Click the button to install and set it "
                        + "up automatically \u2014 Windows will ask for administrator "
                        + "permission once.", "pill-warn"),
                installButton(w));
        wgBox.getStyleClass().add("card");
        boolean wgOk = KeyManager.findWgBinary(w.app().context().runner,
                w.app().context().config().wgBinaryDir()).isPresent();
        wgBox.setVisible(!wgOk);
        wgBox.setManaged(!wgOk);

        Label gwKey = Ui.label("", "form-hint");
        gwKey.setWrapText(true);
        Button copyKey = new Button("Copy public key");
        copyKey.getStyleClass().add("button-secondary");
        copyKey.setOnAction(e -> copyToClipboard(gwKey.getText()));
        HBox keyRow = new HBox(10, copyKey,
                Ui.label("The client configuration needs this key as its \u201cPeer\u201d "
                        + "public key \u2014 it is public and safe to share.", "form-hint"));
        keyRow.setAlignment(javafx.geometry.Pos.CENTER_LEFT);
        renderKey(w, wgOk, gwKey, copyKey);
        VBox keyBox = new VBox(8,
                Ui.label("GATEWAY PUBLIC KEY (share with clients)", "card-title"),
                gwKey, keyRow);
        keyBox.getStyleClass().add("card");
        if (!wgOk) {
            watchForWireGuard(w, gwKey, copyKey);
        }

        GridPane grid = new GridPane();
        grid.setHgap(12);
        grid.setVgap(10);
        addRow(grid, 0, "Gateway name", name);
        addRow(grid, 1, "Listen port (UDP)", port);
        addRow(grid, 2, "VPN subnet", vpnSubnet);
        addRow(grid, 3, "Company LAN subnet", lanCidr);
        addRow(grid, 4, "Company endpoint (public, copyable)", endpoint);
        addRow(grid, 5, "LAN interface", lanIface);

        Label detectNote = Ui.label("", "pill-ok");
        detectNote.setVisible(false);
        Button autoDetect = new Button("Auto-detect company LAN \u2026");
        autoDetect.getStyleClass().add("button-secondary");
        autoDetect.setOnAction(e -> {
            var network = w.app().context().network;
            boolean any = false;
            var lanCidrDetected = network.detectLanCidr();
            if (lanCidrDetected.isPresent()) {
                lanCidr.setText(lanCidrDetected.get());
                any = true;
            }
            var ifaceDetected = network.findPhysical();
            if (ifaceDetected.isPresent()
                    && ifaceDetected.get().name() != null && !ifaceDetected.get().name().isBlank()) {
                lanIface.setText(ifaceDetected.get().name());
                any = true;
            }
            if (vpnSubnet.getText().isBlank()) {
                vpnSubnet.setText("10.50.0.0/24");
                any = true;
            }
            detectNote.setText(any
                    ? "Detected: LAN subnet \u201c" + lanCidr.getText() + "\u201d, interface \u201c"
                    + lanIface.getText() + "\u201d. Review and adjust below; the public endpoint "
                    + "must stay your own DNS name or public IP (it cannot be auto-detected)."
                    : "Could not detect a LAN automatically \u2014 enter the values manually below.");
            detectNote.getStyleClass().setAll("pill", "pill-ok");
            detectNote.setVisible(true);
        });

        w.setNext("Start gateway", () -> {
            error.setVisible(false);
            int p;
            try {
                p = Integer.parseInt(port.getText().trim());
                if (p < 1 || p > 65535) {
                    throw new NumberFormatException();
                }
            } catch (NumberFormatException ex) {
                error.setText("Listen port must be a number between 1 and 65535.");
                error.setVisible(true);
                return;
            }
            try {
                IpHelpers.parseCidr(vpnSubnet.getText().trim());
                if (!lanCidr.getText().isBlank()) {
                    IpHelpers.parseCidr(lanCidr.getText().trim());
                }
            } catch (IllegalArgumentException ex) {
                error.setText("Invalid subnet: " + ex.getMessage());
                error.setVisible(true);
                return;
            }
            AppConfig cfg = w.app().context().config()
                    .with("mode", "SERVER")
                    .with("name", name.getText().isBlank() ? "Company Gateway" : name.getText().trim())
                    .with("server.name", name.getText().isBlank() ? "Company Gateway" : name.getText().trim())
                    .with("server.listenPort", p)
                    .with("server.vpnSubnet", vpnSubnet.getText().trim())
                    .with("server.lan", lanCidr.getText().trim())
                    .with("server.host", endpoint.getText().trim())
                    .with("server.lanInterface", lanIface.getText().trim());
            try {
                w.app().context().configManager.save(cfg);
            } catch (Exception e) {
                error.setText("Could not save configuration: " + e.getMessage());
                error.setVisible(true);
                return;
            }
            w.finish(cfg);
        }, false);

        VBox body = new VBox(14,
                Ui.label("PUBLIC ENDPOINT\nThe address clients will use to reach the gateway:", "form-label"),
                endpoint,
                Ui.label("The client will reach this address over UDP on the port above. "
                        + "Set a DNS name or public IP \u2014 it is copy/paste-able "
                        + "like every other field on this page.", "form-hint"));

        VBox main = new VBox(14, wgBox, keyBox, grid,
                Ui.hbox(10, autoDetect, detectNote), body, error);
        ScrollPane scroll = new ScrollPane(main);
        scroll.setFitToWidth(true);
        scroll.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);
        scroll.setVbarPolicy(ScrollPane.ScrollBarPolicy.AS_NEEDED);
        getChildren().add(scroll);
        setPadding(new Insets(6, 6, 0, 6));
    }

    private static void renderKey(SetupWizard w, boolean wgOk, Label gwKey, Button copyKey) {
        String key = wgOk ? serverPublicKey(w) : "";
        boolean show = wgOk && !key.isBlank();
        gwKey.setText(show ? key
                : "The gateway public key appears here once WireGuard is installed "
                + "\u2014 click the button above.");
        copyKey.setVisible(show);
        copyKey.setManaged(show);
    }

    private static void watchForWireGuard(SetupWizard w, Label gwKey, Button copyKey) {
        Timeline poll = new Timeline();
        KeyFrame kf = new KeyFrame(Duration.seconds(2), ev -> {
            if (KeyManager.findWgBinary(w.app().context().runner,
                    w.app().context().config().wgBinaryDir()).isPresent()) {
                poll.stop();
                renderKey(w, true, gwKey, copyKey);
            }
        });
        poll.getKeyFrames().setAll(kf);
        poll.setCycleCount(Animation.INDEFINITE);
        poll.play();
    }

    private static String serverPublicKey(SetupWizard w) {
        try {
            var vpn = w.app().context().vpn();
            if (vpn != null) {
                return vpn.ensureServerKeys().publicKey();
            }
        } catch (Exception ignored) {
            // fall through to the "not available yet" message
        }
        return "";
    }

    private static void copyToClipboard(String text) {
        ClipboardContent content = new ClipboardContent();
        content.putString(text);
        Clipboard.getSystemClipboard().setContent(content);
    }

    private static Button installButton(SetupWizard w) {
        Button install = new Button("Install WireGuard automatically");
        install.getStyleClass().add("button-primary");
        install.setOnAction(e -> w.app().installDependencies());
        return install;
    }

    private static void addRow(GridPane grid, int row, String label, javafx.scene.Node field) {
        Label l = Ui.label(label.toUpperCase(), "form-label");
        grid.add(l, 0, row);
        grid.add(field, 1, row);
        GridPane.setHgrow(field, Priority.ALWAYS);
        GridPane.setFillWidth(field, true);
    }
}