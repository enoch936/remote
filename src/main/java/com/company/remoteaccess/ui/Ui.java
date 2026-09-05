package com.company.remoteaccess.ui;

import javafx.animation.FadeTransition;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Label;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.util.Duration;

/** Shared UI construction helpers (kept dependency-light on purpose). */
public final class Ui {

    private Ui() {
    }

    public static Label label(String text, String styleClass) {
        Label l = new Label(text);
        l.getStyleClass().add(styleClass);
        return l;
    }

    /** A card containing a title, value and small caption. */
    public static VBox statCard(String title, String value, String caption) {
        VBox card = new VBox(4);
        card.getStyleClass().add("card");
        card.setMinWidth(150);
        card.setAlignment(Pos.CENTER_LEFT);
        Label t = label(title.toUpperCase(), "card-title");
        Label v = label(value, "card-value");
        Label c = label(caption == null ? "" : caption, "card-small");
        card.getChildren().addAll(t, v, c);
        return card;
    }

    public static HBox infoRow(String name, String value) {
        Label n = label(name, "card-title");
        Label v = label(value, "card-small");
        v.getStyleClass().add("card-value");
        v.setStyle("-fx-font-size: 13px; -fx-font-weight: bold;");
        HBox row = new HBox(8);
        row.setAlignment(Pos.CENTER_LEFT);
        HBox.setHgrow(n, Priority.ALWAYS);
        row.getChildren().addAll(n, v);
        return row;
    }

    public static Label pill(String text, String variant) {
        Label p = new Label(text);
        p.getStyleClass().addAll("pill", "pill-" + variant);
        return p;
    }

    public static void fadeIn(Node node, double seconds) {
        FadeTransition ft = new FadeTransition(Duration.seconds(seconds), node);
        ft.setFromValue(0);
        ft.setToValue(1);
        ft.play();
    }

    /** Header row of a section. */
    public static HBox sectionHeader(String title, Node trailing) {
        Label t = label(title, "card-title");
        t.setStyle("-fx-font-size: 13px;");
        HBox box = new HBox();
        box.setAlignment(Pos.CENTER_LEFT);
        HBox.setHgrow(t, Priority.ALWAYS);
        if (trailing != null) {
            box.getChildren().add(trailing);
        }
        box.getChildren().add(0, t);
        box.setPadding(new Insets(0, 0, 8, 0));
        return box;
    }

    public static Region spacer() {
        Region r = new Region();
        HBox.setHgrow(r, Priority.ALWAYS);
        return r;
    }

    public static VBox vbox(double spacing, Node... nodes) {
        VBox v = new VBox(spacing);
        v.getChildren().addAll(nodes);
        return v;
    }

    public static HBox hbox(double spacing, Node... nodes) {
        HBox h = new HBox(spacing);
        h.getChildren().addAll(nodes);
        return h;
    }
}