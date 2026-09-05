package com.company.remoteaccess.ui.setup;

import com.company.remoteaccess.MainApp;
import com.company.remoteaccess.core.configuration.AppConfig;
import com.company.remoteaccess.ui.Ui;
import javafx.geometry.Insets;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;

/**
 * Client setup: the operator pastes the pairing payload printed by the gateway
 * (QR / clipboard) and names the device. Also shows this machine's WireGuard
 * public key, which the gateway admin pastes when creating the pairing code.
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

        Label key = Ui.label(selfPublicKey(w) + keyHint(), "form-hint");
        key.setWrapText(true);

        setNextUi(w, payload, deviceName, error);
        VBox box = new VBox(10,
                Ui.label("PAIRING CODE", "form-label"), payload,
                Ui.label("YOUR DEVICE NAME", "form-label"), deviceName,
                error,
                Ui.label("YOUR PUBLIC KEY (share with the gateway admin)", "card-title"), key);
        getChildren().add(box);
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
                w.app().context().configManager
                        .save(w.app().context().config().with("mode", "CLIENT"));
                w.finish(w.app().context().config());
            } catch (Exception e) {
                error.setText(e.getMessage());
                error.setVisible(true);
            }
        }, false);
    }

    private static String selfPublicKey(SetupWizard w) {
        try {
            var vpn = w.app().context().vpn();
            if (vpn == null) {
                return "WireGuard is not installed yet \u2014 install it to see your public key.";
            }
            return vpn.ensureClientKeys().publicKey();
        } catch (Exception e) {
            return "Could not read the local key: " + e.getMessage();
        }
    }

    private static String keyHint() {
        return "\n\nThe gateway admin needs this public key before issuing a pairing code. "
                + "This key is public and safe to share.";
    }
}