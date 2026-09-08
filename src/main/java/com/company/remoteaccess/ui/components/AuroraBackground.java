package com.company.remoteaccess.ui.components;

import javafx.animation.Animation;
import javafx.animation.Interpolator;
import javafx.animation.Timeline;
import javafx.beans.binding.DoubleBinding;
import javafx.beans.property.ReadOnlyDoubleProperty;
import javafx.scene.CacheHint;
import javafx.scene.effect.BlendMode;
import javafx.scene.layout.Pane;
import javafx.scene.paint.Color;
import javafx.scene.paint.CycleMethod;
import javafx.scene.paint.RadialGradient;
import javafx.scene.paint.Stop;
import javafx.scene.shape.Ellipse;
import javafx.util.Duration;

/**
 * Decorative aurora blobs behind the glass UI. Mouse-transparent, never
 * intercepts clicks. Modes via {@code -Dcra.aurora=value}:
 * <ul>
 *   <li>{@code static} (default) — blobs painted once and cached; near-zero
 *       idle CPU, ideal for VMs / congested desktops.</li>
 *   <li>{@code animated} — slow drift animation for capable GPUs.</li>
 *   <li>{@code off} — fully disabled.</li>
 * </ul>
 */
public final class AuroraBackground extends Pane {

    private static final String MODE =
            System.getProperty("cra.aurora", "static").trim().toLowerCase();
    private static final boolean ANIMATED = "animated".equals(MODE);
    private static final boolean ENABLED = !"off".equals(MODE);

    private static final double[][] CONFIG = {
            {0.18, 0.24, -1},   // azure, ~1/5 across, ~1/4 down
            {0.72, 0.18, 1},    // violet
            {0.42, 0.76, -1},   // cyan
    };

    public AuroraBackground() {
        getStyleClass().add("aurora");
        setMouseTransparent(true);
        setFocusTraversable(false);
        setManaged(false);
        if (!ENABLED) {
            return;
        }

        double[] rx = {0.50, 0.44, 0.52};
        double[] ry = {0.42, 0.38, 0.44};

        for (int i = 0; i < CONFIG.length; i++) {
            Color col = switch (i) {
                case 0 -> Color.rgb(61, 102, 255, 0.55);
                case 1 -> Color.rgb(139, 92, 246, 0.48);
                default -> Color.rgb(34, 211, 238, 0.40);
            };
            Ellipse blob = blob(col);
            blob.setCache(true);
            blob.setCacheHint(CacheHint.SPEED);
            blob.centerXProperty().bind(percent(widthProperty(), CONFIG[i][0]));
            blob.centerYProperty().bind(percent(heightProperty(), CONFIG[i][1]));
            blob.radiusXProperty().bind(percent(widthProperty(), rx[i]));
            blob.radiusYProperty().bind(percent(heightProperty(), ry[i]));
            getChildren().add(blob);
            if (ANIMATED) {
                drift(blob, 18 + i * 7, 26 + i * 12, (int) CONFIG[i][2]);
            }
        }
    }

    private static DoubleBinding percent(ReadOnlyDoubleProperty base, double pct) {
        return base.multiply(pct);
    }

    private static Ellipse blob(Color color) {
        RadialGradient g = new RadialGradient(
                0, 0, 0.5, 0.5, 0.5, true, CycleMethod.NO_CYCLE,
                new Stop(0.0, color),
                new Stop(1.0, Color.rgb(0, 0, 0, 0)));
        Ellipse e = new Ellipse();
        e.setFill(g);
        e.setBlendMode(BlendMode.SOFT_LIGHT);
        e.setOpacity(0.85);
        return e;
    }

    private static void drift(Ellipse e, double seconds, double amplitude, int dir) {
        double a = dir * amplitude;
        double b = dir * amplitude * 0.55;
        Timeline loop = new Timeline(
                new javafx.animation.KeyFrame(Duration.ZERO,
                        new javafx.animation.KeyValue(e.translateXProperty(), 0.0),
                        new javafx.animation.KeyValue(e.translateYProperty(), 0.0)),
                new javafx.animation.KeyFrame(Duration.seconds(seconds),
                        new javafx.animation.KeyValue(e.translateXProperty(), a, Interpolator.EASE_BOTH),
                        new javafx.animation.KeyValue(e.translateYProperty(), b, Interpolator.EASE_BOTH)));
        loop.setAutoReverse(true);
        loop.setCycleCount(Animation.INDEFINITE);
        loop.play();
    }
}