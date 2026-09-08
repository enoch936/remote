package com.company.remoteaccess.ui.setup;

import com.company.remoteaccess.core.configuration.AppConfig;
import com.company.remoteaccess.ui.Ui;
import com.company.remoteaccess.vpn.KeyManager;
import javafx.animation.Animation;
import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.geometry.Insets;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.util.Duration;

/**
 * Client setup: the operator pastes the pairing payload printed by the gateway
 * (QR / clipboard) and names the device. Also shows this machine's WireGuard
 * public key, which the gateway admin pastes when creating the pairing code.
 * When WireGuard is missing it offers a one-click automatic install and keeps
 * watching so the public key appears as soon as the install finishes.
 */
final class ClientSetupPage extends VBox {

    ClientSetupPage(SetupWizard w) {
        w.setTitle("Connect to your company network", "");
        w.setBack(w::showWelcome, true);

        TextArea payload = new TextArea();
        payload.setPromptText("paste the pairing code from your administrator here");
        payload.setPrefRowCount(4);

        TextField deviceName = new TextField();
        deviceName.setPromptText("device name (must match the gateway admin's entry)");
        deviceName.setText(System.getProperty("user.name", "my-computer"));

        Label error = Ui.label("", "pill-err");
        error.setVisible(false);

        Label wgNote = Ui.label("", "pill-warn");
        wgNote.setWrapText(true);
        Button install = new Button("Install WireGuard automatically");
        install.getStyleClass().add("button-primary");
        install.setOnAction(e -> w.app().installDependencies());
        VBox wgBox = new VBox(8, wgNote, install);
        wgBox.getStyleClass().add("card");

        Label key = Ui.label("", "form-hint");
        key.setWrapText(true);

        Button copyKey = new Button("Copy public key");
        copyKey.getStyleClass().add("button-secondary");
        copyKey.setOnAction(e -> {
            String text = key.getText();
            text = text.substring(0, text.indexOf('\n') == -1 ? text.length() : text.indexOf('\n'));
            javafx.scene.input.ClipboardContent content = new javafx.scene.input.ClipboardContent();
            content.putString(text.trim());
            javafx.scene.input.Clipboard.getSystemClipboard().setContent(content);
        });

        HBox keyRow = new HBox(10, copyKey,
                Ui.label("Select-and-copy also works, but this button copies just the key.",
                        "form-hint"));
        keyRow.setAlignment(javafx.geometry.Pos.CENTER_LEFT);

        boolean wgOk = KeyManager.findWgBinary(w.app().context().runner,
                w.app().context().config().wgBinaryDir()).isPresent();
        renderWgState(w, wgOk, wgNote, wgBox, key);

        setNextUi(w, payload, deviceName, error);
        VBox box = new VBox(10,
                Ui.label("PAIRING CODE", "form-label"), payload,
                Ui.label("HOW IT WORKS", "form-label"),
                Ui.label("1. The gateway administrator clicks \u201cPair a device\u201d on "
                        + "their server dashboard and enters the name + public key below.\n"
                        + "2. They give you the generated pairing code.\n"
                        + "3. Paste that code here, type the device name exactly as the "
                        + "administrator registered it, and click \u201cPair\u201d.", "form-hint"),
                Ui.label("YOUR DEVICE NAME", "form-label"), deviceName,
                error,
                wgBox,
                Ui.label("YOUR PUBLIC KEY (share with the gateway admin)", "card-title"),
                key, keyRow);
        ScrollPane scroll = new ScrollPane(box);
        scroll.setFitToWidth(true);
        scroll.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);
        scroll.setVbarPolicy(ScrollPane.ScrollBarPolicy.AS_NEEDED);
        getChildren().add(scroll);
        setPadding(new Insets(6, 6, 0, 6));

        if (!wgOk) {
            watchForWireGuard(w, wgNote, wgBox, key);
        }
    }

    private static void renderWgState(SetupWizard w, boolean present,
                                      Label wgNote, VBox wgBox, Label key) {
        boolean show = !present;
        wgNote.setText(show
                ? "WireGuard is not installed on this machine. Click the button to install "
                + "and set it up automatically \u2014 Windows will ask for administrator "
                + "permission once."
                : "WireGuard is installed \u2014 the key below can be shared with the admin.");
        wgBox.setVisible(show);
        wgBox.setManaged(show);

        String pub = present ? localPublicKey(w) : "";
        key.setText((present
                ? pub
                : "WireGuard is not installed yet \u2014 it installs automatically from the "
                + "button above if you want \u2014 and then your public key appears here.")
                + keyHint());
    }

    private static void watchForWireGuard(SetupWizard w, Label wgNote, VBox wgBox, Label key) {
        Timeline poll = new Timeline();
        KeyFrame kf = new KeyFrame(Duration.seconds(2), ev -> {
            if (KeyManager.findWgBinary(w.app().context().runner,
                    w.app().context().config().wgBinaryDir()).isPresent()) {
                poll.stop();
                renderWgState(w, true, wgNote, wgBox, key);
            }
        });
        poll.getKeyFrames().setAll(kf);
        poll.setCycleCount(Animation.INDEFINITE);
        poll.play();
    }

    private static String localPublicKey(SetupWizard w) {
        try {
            var vpn = w.app().context().vpn();
            if (vpn != null) {
                return vpn.ensureClientKeys().publicKey();
            }
        } catch (Exception ignored) {
            // fall through to the generic message
        }
        return "WireGuard is installed but the key could not be generated yet.";
    }

    private void setNextUi(SetupWizard w, TextArea payload, TextField deviceName, Label error) {
        w.setNext("Pair", () -> {
            error.setVisible(false);
            String raw = payload.getText().trim();
            String name = deviceName.getText().trim();
            if (raw.isBlank() || name.isBlank()) {
                error.setText("A pairing code and a device name are required.");
                error.setVisible(true);
                return;
            }
            try {
                w.app().clientService().completePairing(
                        com.company.remoteaccess.security.PairingToken.fromPayload(raw), name);
                AppConfig cfg = w.app().context().config().with("mode", "CLIENT");
                w.app().context().configManager.save(cfg);
                w.finish(cfg);
            } catch (Exception e) {
                error.setText(e.getMessage());
                error.setVisible(true);
            }
        }, false);
    }

    private static String keyHint() {
        return "\n\nThe gateway admin needs this public key before issuing a pairing code. "
                + "This key is public and safe to share.";
    }
}