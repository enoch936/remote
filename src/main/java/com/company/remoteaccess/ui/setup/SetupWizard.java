package com.company.remoteaccess.ui.setup;

import com.company.remoteaccess.MainApp;
import com.company.remoteaccess.core.configuration.AppConfig;
import com.company.remoteaccess.ui.Ui;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.RadioButton;
import javafx.scene.control.ToggleGroup;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.Window;

import java.util.function.Consumer;

/**
 * First-run setup wizard: pick a role (CLIENT or SERVER) and complete the data
 * needed to start. Returns the final {@link AppConfig} via {@link #onComplete}.
 */
public final class SetupWizard {

    private final MainApp app;
    private final Stage stage = new Stage();
    private final StackPane content = new StackPane();
    private final Label stepTitle = Ui.label("Welcome", "app-title");
    private final Label stepHint = Ui.label("", "form-hint");
    private final Button back = new Button("Back");
    private final Button next = new Button("Next");
    private Consumer<AppConfig> onComplete;
    private VBox current;

    public SetupWizard(MainApp app) {
        this.app = app;

        back.getStyleClass().addAll("button-ghost");
        next.getStyleClass().add("button-primary");

        HBox footer = new HBox(10, back, spacer(), next);
        footer.setAlignment(Pos.CENTER_RIGHT);
        footer.setPadding(new Insets(12, 18, 18, 18));

        VBox headerBox = new VBox(4, stepTitle, stepHint);
        stepHint.setWrapText(true);
        stepHint.setMaxWidth(520);
        headerBox.setPadding(new Insets(18, 18, 0, 18));

        VBox root = new VBox(10, headerBox, content, footer);
        root.getStyleClass().addAll("root", "dark");
        VBox.setVgrow(content, Priority.ALWAYS);

        Scene scene = new Scene(root, 580, 500);
        scene.getStylesheets().add(getClass().getResource("/styles.css").toExternalForm());
        stage.setScene(scene);
        Ui.enhance(root);
    }

    private static Region spacer() {
        Region r = new Region();
        HBox.setHgrow(r, Priority.ALWAYS);
        return r;
    }

    public void show(Window owner) {
        if (owner != null) {
            stage.initOwner(owner);
        }
        stage.initModality(Modality.WINDOW_MODAL);
        stage.show();
        setPage(new WelcomePage(this));
    }

    public void onComplete(Consumer<AppConfig> cb) {
        this.onComplete = cb;
    }

    // ------------------------------------------------------------------
    // navigation
    // ------------------------------------------------------------------

    void setTitle(String title, String hint) {
        stepTitle.setText(title);
        stepHint.setText(hint);
    }

    void setNext(String text, Runnable action, boolean disabled) {
        next.setText(text);
        next.setDisable(disabled);
        next.setOnAction(e -> action.run());
    }

    void hideNext() {
        next.setVisible(false);
    }

    void setBack(Runnable action, boolean enabled) {
        back.setDisable(!enabled);
        back.setOnAction(e -> {
            if (action != null) {
                action.run();
            }
        });
    }

    void setPage(VBox page) {
        current = page;
        content.getChildren().setAll(page);
        Ui.enhance(page);
    }

    /** Back navigation for wizard pages. */
    void showWelcome() {
        setPage(new WelcomePage(this));
    }

    void finish(AppConfig cfg) {
        stage.close();
        if (onComplete != null) {
            // Record that the first-run role/setup choice was completed.
            onComplete.accept(cfg.with("app.setupDone", true));
        }
    }

    MainApp app() {
        return app;
    }

    // ------------------------------------------------------------------

    private static final class WelcomePage extends VBox {
        WelcomePage(SetupWizard w) {
            w.setTitle("How will you use this computer?", "");
            w.setBack(w::showWelcome, false);

            RadioButton client = new RadioButton(
                    "This is my HOME computer \u2014 I want to reach my company network");
            RadioButton server = new RadioButton(
                    "This is the COMPANY gateway \u2014 run the VPN here");
            ToggleGroup group = new ToggleGroup();
            client.setToggleGroup(group);
            server.setToggleGroup(group);
            // Keep the last chosen role pre-selected when the chooser re-runs.
            if (w.app().context().config().mode() == com.company.remoteaccess.core.state.Role.SERVER) {
                server.setSelected(true);
            } else {
                client.setSelected(true);
            }

            w.setNext("Continue",
                    () -> w.setPage(server.isSelected()
                            ? new ServerSetupPage(w)
                            : new ClientSetupPage(w)),
                    false);

            getChildren().add(new VBox(14, client, server,
                    Ui.label("The gateway needs administrator privileges. "
                            + "The client only needs them while connecting.", "form-hint"),
                    Ui.label("Requirements: WireGuard (wg) installed on both "
                            + "machines, and administrator rights on the gateway. "
                            + "You can check this later under Settings or with "
                            + "--diagnostics.", "form-hint")));
            setPadding(new Insets(6, 6, 0, 6));
        }
    }
}