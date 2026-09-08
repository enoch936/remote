package com.company.remoteaccess.ui.server;

import com.company.remoteaccess.core.configuration.AppConfig;
import com.company.remoteaccess.networking.IpHelpers;
import com.company.remoteaccess.security.PairingManager;
import com.company.remoteaccess.security.PairingToken;
import com.company.remoteaccess.security.Validation;
import com.company.remoteaccess.server.ClientRegistry;
import com.company.remoteaccess.server.ServerPeer;
import com.company.remoteaccess.ui.Ui;
import com.company.remoteaccess.vpn.VpnException;
import com.company.remoteaccess.vpn.VpnManager;
import com.company.remoteaccess.vpn.VpnStatus;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.image.ImageView;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.Window;

import java.util.Optional;

/**
 * Server-side device pairing dialog.
 *
 * <p>Registers a device (device name + its WireGuard public key), assigns the
 * next free VPN address and prints a one-time pairing payload as QR text that the
 * client enters. Tokens are single-use and short-lived.
 */
public final class PairDeviceDialog {

    private PairDeviceDialog() {
    }

    public static void show(Window owner, ClientRegistry registry, PairingManager pairingManager,
                            AppConfig cfg, String serverPublicKey) {
        Stage dialog = new Stage();
        dialog.initOwner(owner);
        dialog.initModality(Modality.APPLICATION_MODAL);
        dialog.setTitle("Pair a new device");

        TextField name = new TextField();
        name.setPromptText("e.g. john-laptop");
        TextField pubKey = new TextField();
        pubKey.setPromptText("paste the client\u2019s WireGuard public key");

        Label error = Ui.label("", "pill-err");
        error.setVisible(false);

        Button cancel = new Button("Cancel");
        cancel.getStyleClass().add("button-ghost");
        cancel.setOnAction(e -> dialog.close());

        Button generate = new Button("Generate pairing code");
        generate.getStyleClass().add("button-primary");

        VBox fields = Ui.vbox(10,
                Ui.label("DEVICE NAME", "form-label"), name,
                Ui.label("CLIENT PUBLIC KEY", "form-label"), pubKey,
                error);
        HBox actions = new HBox(10, cancel, generate);
        actions.setAlignment(Pos.CENTER_RIGHT);

        VBox root = Ui.vbox(12, fields, actions);
        root.setPadding(new Insets(18));

        generate.setOnAction(e -> {
            error.setVisible(false);
            String deviceName = name.getText().trim();
            String publicKey = pubKey.getText().trim();
            if (deviceName.isBlank() || publicKey.isBlank()) {
                error.setText("Device name and public key are required.");
                error.setVisible(true);
                return;
            }
            String assignedIp = nextFreeIp(registry, cfg);
            if (assignedIp == null) {
                error.setText("No free VPN addresses left in " + cfg.vpnSubnet());
                error.setVisible(true);
                return;
            }
            try {
                registry.add(deviceName, publicKey, assignedIp);
            } catch (IllegalArgumentException ex) {
                error.setText(ex.getMessage());
                error.setVisible(true);
                return;
            }

            String host = effectiveHost(cfg);
            PairingToken payload = new PairingToken(cfg.serverName(), host, cfg.listenPort(),
                    serverPublicKey, assignedIp,
                    pairingManager.issue(deviceName, publicKey));
            showResult(dialog, assignedIp, payload);
        });

        Scene scene = new Scene(root, 480, 300);
        scene.getStylesheets().add(PairDeviceDialog.class.getResource("/styles.css").toExternalForm());
        dialog.setScene(scene);
        Ui.enhance(scene.getRoot());
        dialog.showAndWait();
    }

    /**
     * Key rotation for an existing device: revoke the old key, register the new
     * key under the same VPN address and issue a fresh single-use pairing code.
     * The old key is removed from a running tunnel immediately (best effort).
     */
    public static void showRotate(Window owner, ClientRegistry registry, PairingManager pairingManager,
                                  AppConfig cfg, String serverPublicKey, VpnManager vpn,
                                  ServerPeer existing) {
        if (existing == null || existing.status != ServerPeer.Status.AUTHORIZED) {
            return;
        }
        Stage dialog = new Stage();
        dialog.initOwner(owner);
        dialog.initModality(Modality.APPLICATION_MODAL);
        dialog.setTitle("Replace key \u2014 " + existing.deviceName);

        TextField name = new TextField(existing.deviceName);
        TextField pubKey = new TextField();
        pubKey.setPromptText("paste the client\u2019s NEW WireGuard public key");

        Label error = Ui.label("", "pill-err");
        error.setVisible(false);

        Button cancel = new Button("Cancel");
        cancel.getStyleClass().add("button-ghost");
        cancel.setOnAction(e -> dialog.close());

        Button rotate = new Button("Rotate key & generate code");
        rotate.getStyleClass().add("button-primary");

        VBox fields = Ui.vbox(10,
                Ui.label("DEVICE NAME", "form-label"), name,
                Ui.label("NEW CLIENT PUBLIC KEY", "form-label"), pubKey,
                error);
        HBox actions = new HBox(10, cancel, rotate);
        actions.setAlignment(Pos.CENTER_RIGHT);

        VBox root = Ui.vbox(12, fields, actions);
        root.setPadding(new Insets(18));

        rotate.setOnAction(e -> {
            error.setVisible(false);
            String deviceName = name.getText().trim();
            String publicKey = pubKey.getText().trim();
            try {
                Validation.requireDeviceName(deviceName, "device name");
                Validation.requireWireGuardKey(publicKey, "client public key");
            } catch (IllegalArgumentException ex) {
                error.setText(ex.getMessage());
                error.setVisible(true);
                return;
            }
            if (existing.publicKey.equals(publicKey)) {
                error.setText("Enter a NEW key, not the key already in use.");
                error.setVisible(true);
                return;
            }
            boolean duplicateKey = registry.all().stream().anyMatch(d ->
                    d.publicKey.equals(publicKey) && !d.deviceName.equalsIgnoreCase(existing.deviceName));
            if (duplicateKey) {
                error.setText("A device with this public key is already registered.");
                error.setVisible(true);
                return;
            }
            try {
                registry.revoke(existing.deviceName);
                registry.add(deviceName, publicKey, existing.vpnAddress);
            } catch (IllegalArgumentException ex) {
                error.setText(ex.getMessage());
                error.setVisible(true);
                return;
            }
            dropLivePeer(vpn, cfg, existing.publicKey);
            String host = effectiveHost(cfg);
            PairingToken payload = new PairingToken(cfg.serverName(), host, cfg.listenPort(),
                    serverPublicKey, existing.vpnAddress,
                    pairingManager.issue(deviceName, publicKey));
            showResult(dialog, existing.vpnAddress, payload);
        });

        Scene scene = new Scene(root, 480, 300);
        scene.getStylesheets().add(PairDeviceDialog.class.getResource("/styles.css").toExternalForm());
        dialog.setScene(scene);
        Ui.enhance(scene.getRoot());
        dialog.showAndWait();
    }

    private static void dropLivePeer(VpnManager vpn, AppConfig cfg, String oldPublicKey) {
        if (vpn == null || oldPublicKey == null) {
            return;
        }
        try {
            VpnStatus st = vpn.status();
            if (st != null && st.running()) {
                vpn.adapter().removePeer(cfg.tunnelName(), oldPublicKey);
            }
        } catch (VpnException ignored) {
            // revoked key may linger until the next rebootstrap regenerates peers
        }
    }

    private static void showResult(Stage dialog, String assignedIp, PairingToken payload) {
        ImageView qr = new ImageView(Qr.render(payload.toPayload()));
        qr.setFitWidth(230);
        qr.setFitHeight(230);

        TextArea code = new TextArea(payload.toPayload());
        code.setEditable(false);
        code.setPrefRowCount(6);
        code.setFont(javafx.scene.text.Font.font("monospace", 11));

        Button copy = new Button("Copy payload");
        copy.getStyleClass().add("button-secondary");
        copy.setOnAction(e -> {
            ClipboardContent c = new ClipboardContent();
            c.putString(payload.toPayload());
            Clipboard.getSystemClipboard().setContent(c);
            copy.setText("Copied");
        });

        Label summary = Ui.label("Assigned VPN IP: \u2022 " + assignedIp
                + "\nWireGuard public key: " + payload.serverPublicKey()
                + "\n\nShare this code with the client \u2014 it expires in 10 minutes.",
                "form-hint");
        summary.setWrapText(true);

        Button done = new Button("Done");
        done.getStyleClass().add("button-primary");
        done.setOnAction(e -> dialog.close());

        VBox right = Ui.vbox(10, Ui.label("PAIRING CODE", "card-title"), code, copy, summary, done);
        HBox content = new HBox(18, qr, right);
        content.setAlignment(Pos.TOP_LEFT);
        content.setPadding(new Insets(18));

        VBox.setVgrow(right, Priority.ALWAYS);
        dialog.getScene().setRoot(content);
        Ui.enhance(content);
        dialog.setWidth(Math.max(dialog.getWidth(), 720));
    }

    private static String effectiveHost(AppConfig cfg) {
        if (cfg.serverHost() != null && !cfg.serverHost().isBlank()) {
            return cfg.serverHost();
        }
        return "gateway.local";
    }

    /** First free host of the VPN subnet after the gateway (.1). */
    private static String nextFreeIp(ClientRegistry registry, AppConfig cfg) {
        IpHelpers.Cidr cidr = IpHelpers.parseCidr(cfg.vpnSubnet());
        long start = 2;
        long usable = (1L << (32 - cidr.prefix())) - 2;
        long end = Math.min(start + 199, usable);
        for (long i = start; i <= end; i++) {
            String candidate = IpHelpers.host(cidr, i);
            Optional<String> taken = registry.all().stream()
                    .map(d -> d.vpnAddress)
                    .filter(candidate::equals)
                    .findAny();
            if (taken.isEmpty()) {
                return candidate;
            }
        }
        return null;
    }
}