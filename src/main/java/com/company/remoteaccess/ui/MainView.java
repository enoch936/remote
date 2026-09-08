package com.company.remoteaccess.ui;

import com.company.remoteaccess.BuildInfo;
import com.company.remoteaccess.MainApp;
import com.company.remoteaccess.core.state.Role;
import com.company.remoteaccess.ui.components.AuroraBackground;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;

/**
 * Main window shell: header, content area and footer. Switches between
 * dashboards and settings without recreating the stage.
 */
public final class MainView {

    private final MainApp app;
    private final StackPane shell = new StackPane();
    private final BorderPane root = new BorderPane();
    private final StackPane content = new StackPane();
    private final Label footerStatus = new Label("");
    private final Label rolePill = new Label();

    private Node currentPage;

    public MainView(MainApp app) {
        this.app = app;
        shell.getStyleClass().addAll("root", "dark");
        shell.getChildren().addAll(new AuroraBackground(), root);
        root.getStyleClass().add("app-shell");
        root.setTop(buildHeader());
        root.setCenter(content);
        root.setBottom(buildFooter());
    }

    public Parent root() {
        return shell;
    }

    public void applyTheme(String theme) {
        shell.getStyleClass().removeAll("dark", "light");
        shell.getStyleClass().add("light".equalsIgnoreCase(theme) ? "light" : "dark");
    }

    private Node buildHeader() {
        Label title = Ui.label(BuildInfo.name(), "app-title");
        Label subtitle = Ui.label("company remote access gateway", "app-subtitle");
        VBox titles = new VBox(1);
        titles.getChildren().addAll(title, subtitle);

        rolePill.getStyleClass().addAll("pill", "pill-accent");
        refreshRolePill();

        Button settings = new Button("Settings");
        settings.getStyleClass().add("button-secondary");
        settings.setMaxWidth(Double.MAX_VALUE);
        settings.setOnAction(e -> showSettings());

        Button home = new Button("Home");
        home.getStyleClass().add("button-secondary");
        home.setMaxWidth(Double.MAX_VALUE);
        home.setOnAction(e -> showDashboard());

        Button themeToggle = new Button("Theme");
        themeToggle.getStyleClass().add("button-ghost");
        themeToggle.setOnAction(e -> {
            boolean light = shell.getStyleClass().contains("light");
            String next = light ? "dark" : "light";
            app.applyTheme(next);
            try {
                app.context().configManager.save(app.context().config().with("app.theme", next));
            } catch (Exception ignored) {
                // best effort
            }
        });

        HBox right = Ui.hbox(8, home, rolePill, themeToggle, settings);
        right.setAlignment(Pos.CENTER_RIGHT);

        HBox header = new HBox(12);
        header.setAlignment(Pos.CENTER_LEFT);
        header.getStyleClass().add("header-bar");
        HBox trailing = new HBox();
        trailing.setAlignment(Pos.CENTER_RIGHT);
        HBox.setHgrow(trailing, javafx.scene.layout.Priority.ALWAYS);
        header.getChildren().addAll(titles, trailing, right);
        return header;
    }

    private Node buildFooter() {
        Label left = Ui.label(BuildInfo.versionLabel() + "  \u00b7  "
                + "Files stored under ~/.company-remote", "form-hint");
        footerStatus.setText("ready");
        footerStatus.setAlignment(Pos.CENTER_RIGHT);
        HBox footer = new HBox();
        footer.setAlignment(Pos.CENTER_LEFT);
        footer.getStyleClass().add("footer-bar");
        HBox.setHgrow(left, javafx.scene.layout.Priority.ALWAYS);
        footer.getChildren().addAll(left, footerStatus);
        return footer;
    }

    public void refreshRolePill() {
        Role mode = app.role();
        if (mode == Role.CLIENT) {
            rolePill.setText("CLIENT \u00b7 HOME");
        } else if (mode == Role.SERVER) {
            rolePill.setText("SERVER \u00b7 GATEWAY");
        } else {
            rolePill.setText("SETUP REQUIRED");
        }
    }

    public void showDashboard() {
        refreshRolePill();
        setContent(app.role() == Role.SERVER
                ? new com.company.remoteaccess.ui.server.ServerDashboard(app)
                : new com.company.remoteaccess.ui.client.ClientDashboard(app));
        footerStatus.setText("ready");
    }

    public void showSettings() {
        setContent(new com.company.remoteaccess.ui.settings.SettingsView(app));
        footerStatus.setText("settings");
    }

    private void setContent(Node node) {
        if (currentPage != null) {
            content.getChildren().clear();
        }
        currentPage = node;
        if (currentPage != null) {
            Ui.enhance(currentPage);
            content.getChildren().setAll(currentPage);
            Ui.enter(currentPage);
        }
    }

    public void setStatus(String status) {
        footerStatus.setText(status == null ? "" : status);
    }
}