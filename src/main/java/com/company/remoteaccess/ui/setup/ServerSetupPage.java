package com.company.remoteaccess.ui.setup;

import com.company.remoteaccess.core.configuration.AppConfig;
import com.company.remoteaccess.networking.IpHelpers;
import com.company.remoteaccess.ui.Ui;
import javafx.geometry.Insets;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;

/**
 * Server setup: gateway discovery, VPN subnet and company LAN details.
 * Writes the config with mode=SERVER so the application runs as a gateway.
 */
final class ServerSetupPage extends VBox {

    ServerSetupPage(SetupWizard w) {
        w.setTitle("Configure the company gateway", "");

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

        GridPane grid = new GridPane();
        grid.setHgap(12);
        grid.setVgap(10);
        addRow(grid, 0, "Gateway name", name);
        addRow(grid, 1, "Listen port (UDP)", port);
        addRow(grid, 2, "VPN subnet", vpnSubnet);
        addRow(grid, 3, "Company LAN subnet", lanCidr);
        addRow(grid, 4, "Company endpoint", endpoint);
        addRow(grid, 5, "LAN interface", lanIface);

        w.setBack(w::showWelcome, true);
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
                Ui.label("PUBLIC ENDPOINT\nYour gateway heard as:", "form-label"),
                endpoint,
                Ui.label("The client will reach this address over UDP. "
                        + "Set a DNS name or public IP \u2014 the wizard fills "
                        + "\u2018gateway.local\u2019 when left empty.", "form-hint"));
        getChildren().add(new VBox(14, grid, body, error));
        setPadding(new Insets(6, 6, 0, 6));
    }

    private static void addRow(GridPane grid, int row, String label, javafx.scene.Node field) {
        Label l = Ui.label(label.toUpperCase(), "form-label");
        grid.add(l, 0, row);
        grid.add(field, 1, row);
        GridPane.setHgrow(field, Priority.ALWAYS);
        GridPane.setFillWidth(field, true);
    }
}