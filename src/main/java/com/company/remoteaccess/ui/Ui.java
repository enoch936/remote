package com.company.remoteaccess.ui;

import javafx.animation.FadeTransition;
import javafx.animation.Interpolator;
import javafx.animation.ParallelTransition;
import javafx.animation.ScaleTransition;
import javafx.animation.TranslateTransition;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.ButtonBase;
import javafx.scene.control.Label;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.util.Duration;

import java.util.ArrayDeque;
import java.util.Deque;

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
        enter(node, seconds, 8, 0.985);
    }

    /**
     * Modern page entrance: fades in while sliding up and settling from a
     * slight scale — gives page swaps a polished "glass settles" feel.
     */
    public static void enter(Node node) {
        enter(node, 0.28, 10, 0.982);
    }

    public static void enter(Node node, double seconds, double lift, double fromScale) {
        if (node.getProperties().containsKey("ui.entering")) {
            return;
        }
        node.getProperties().put("ui.entering", Boolean.TRUE);
        node.setOpacity(0);
        node.setScaleX(fromScale);
        node.setScaleY(fromScale);
        node.setTranslateY(lift);

        FadeTransition fade = new FadeTransition(Duration.seconds(seconds), node);
        fade.setFromValue(0);
        fade.setToValue(1);

        TranslateTransition slide = new TranslateTransition(Duration.seconds(seconds), node);
        slide.setFromY(lift);
        slide.setToY(0);

        ScaleTransition scale = new ScaleTransition(Duration.seconds(seconds), node);
        scale.setFromX(fromScale);
        scale.setFromY(fromScale);
        scale.setToX(1);
        scale.setToY(1);

        ParallelTransition pt = new ParallelTransition(fade, slide, scale);
        pt.setInterpolator(Interpolator.EASE_OUT);
        pt.setOnFinished(e -> {
            node.setOpacity(1);
            node.setScaleX(1);
            node.setScaleY(1);
            node.setTranslateY(0);
            node.getProperties().remove("ui.entering");
        });
        pt.play();
    }

    /**
     * Walks a subtree and attaches modern button micro-interactions:
     * hover lift, press-down and release spring-back. Idempotent.
     */
    public static void enhance(Node root) {
        Deque<Node> stack = new ArrayDeque<>();
        stack.push(root);
        while (!stack.isEmpty()) {
            Node n = stack.pop();
            if (n instanceof ButtonBase b) {
                attachInteractions(b);
            }
            if (n instanceof javafx.scene.Parent p) {
                stack.addAll(p.getChildrenUnmodifiable());
            }
        }
    }

    private static void attachInteractions(ButtonBase b) {
        if (b.getProperties().containsKey("ui.enhanced")) {
            return;
        }
        b.getProperties().put("ui.enhanced", Boolean.TRUE);

        ScaleTransition lift = scaleTo(b, 1.035, 150);
        ScaleTransition press = scaleTo(b, 0.965, 90);
        ScaleTransition rest = scaleTo(b, 1.0, 180);

        b.addEventHandler(MouseEvent.MOUSE_ENTERED, e -> {
            if (!b.isDisabled()) {
                lift.playFromStart();
            }
        });
        b.addEventHandler(MouseEvent.MOUSE_EXITED, e -> {
            if (!b.isDisabled()) {
                rest.playFromStart();
            }
        });
        b.addEventHandler(MouseEvent.MOUSE_PRESSED, e -> {
            if (!b.isDisabled()) {
                lift.stop();
                press.playFromStart();
            }
        });
        b.addEventHandler(MouseEvent.MOUSE_RELEASED, e -> {
            if (!b.isDisabled() && b.isHover()) {
                press.stop();
                lift.playFromStart();
            }
        });
    }

    private static ScaleTransition scaleTo(Node n, double to, long millis) {
        ScaleTransition st = new ScaleTransition(Duration.millis(millis), n);
        st.setToX(to);
        st.setToY(to);
        st.setInterpolator(Interpolator.EASE_OUT);
        return st;
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