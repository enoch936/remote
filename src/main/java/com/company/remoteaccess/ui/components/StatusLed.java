package com.company.remoteaccess.ui.components;

import javafx.animation.Animation;
import javafx.animation.Interpolator;
import javafx.animation.KeyFrame;
import javafx.animation.KeyValue;
import javafx.animation.Timeline;
import javafx.scene.layout.StackPane;
import javafx.scene.shape.Circle;
import javafx.util.Duration;

/**
 * Pulsing connection-status LED. Colors: gray (idle), green (ok),
 * amber (warning), red (error). Animates while in transient states.
 */
public final class StatusLed extends StackPane {

    public enum Color { IDLE, OK, WARN, ERR }

    private final Circle outer = new Circle(7);
    private final Circle glow = new Circle(5);
    private final Timeline pulse = new Timeline();
    private Color current = Color.IDLE;

    public StatusLed() {
        getChildren().addAll(outer, glow);
        glow.setOpacity(0.55);
        pulse.setCycleCount(Animation.INDEFINITE);
        pulse.getKeyFrames().addAll(
                new KeyFrame(Duration.ZERO,
                        new KeyValue(glow.radiusProperty(), 5, Interpolator.EASE_IN),
                        new KeyValue(glow.opacityProperty(), 0.55)),
                new KeyFrame(Duration.seconds(1.6),
                        new KeyValue(glow.radiusProperty(), 12, Interpolator.EASE_OUT),
                        new KeyValue(glow.opacityProperty(), 0.0)));
        applyColor(current);
    }

    public void setColor(Color color) {
        if (color == null) {
            color = Color.IDLE;
        }
        current = color;
        applyColor(color);
        if (color == Color.IDLE) {
            pulse.stop();
        } else  {
            pulse.stop();
            pulse.playFromStart();
        }
    }

    private void applyColor(Color color) {
        String css = switch (color) {
            case OK -> "led-ok";
            case WARN -> "led-warn";
            case ERR -> "led-err";
            default -> "led";
        };
        outer.getStyleClass().setAll("led", css);
        glow.getStyleClass().setAll("led", css);
    }

    public Color color() {
        return current;
    }
}