package com.company.remoteaccess.ui;

import com.company.remoteaccess.MainApp;
import com.company.remoteaccess.core.state.ConnectionState;
import com.company.remoteaccess.core.state.Role;
import javafx.application.Platform;

import java.awt.AWTException;
import java.awt.MenuItem;
import java.awt.PopupMenu;
import java.awt.SystemTray;
import java.awt.TrayIcon;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.image.BufferedImage;

/** Lightweight AWT system tray integration (JFX dialogs stay in charge). */
public final class AppTray {

    private final MainApp app;
    private TrayIcon icon;
    private final MenuItem toggle = new MenuItem();
    private final MenuItem dashboard = new MenuItem("Open dashboard");
    private final MenuItem settings = new MenuItem("Settings");
    private final MenuItem exit = new MenuItem("Exit");

    public AppTray(MainApp app) {
        this.app = app;
    }

    public boolean installed() {
        return icon != null;
    }

    public void install() {
        if (!SystemTray.isSupported()) {
            return;
        }
        PopupMenu menu = new PopupMenu();
        dashboard.addActionListener(e -> app.showWindow());
        settings.addActionListener(e -> {
            app.showWindow();
            Platform.runLater(() -> app.mainView().showSettings());
        });
        exit.addActionListener(e -> app.shutdown());

        menu.add(toggle);
        menu.add(dashboard);
        menu.add(settings);
        menu.addSeparator();
        menu.add(exit);
        toggle.addActionListener(e -> {
            var svc = app.clientService();
            if (svc == null) {
                return;
            }
            if (svc.state() == ConnectionState.CONNECTED) {
                svc.disconnect();
            } else {
                svc.connect();
            }
        });

        icon = new TrayIcon(iconImage(), "Company Remote Access");
        icon.setImageAutoSize(true);
        icon.setPopupMenu(menu);
        icon.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getButton() == MouseEvent.BUTTON1) {
                    app.showWindow();
                }
            }
        });
        try {
            SystemTray.getSystemTray().add(icon);
        } catch (AWTException e) {
            icon = null;
            return;
        }
        refresh();
    }

    public void refresh() {
        if (icon == null) {
            return;
        }
        if (app.role() == Role.CLIENT && app.clientService() != null) {
            ConnectionState st = app.clientService().state();
            toggle.setLabel(st == ConnectionState.CONNECTED ? "Disconnect" : "Connect");
            toggle.setEnabled(!st.isTransient());
        } else {
            toggle.setEnabled(false);
            toggle.setLabel("Not available");
        }
    }

    public void shutdown() {
        if (icon != null) {
            SystemTray.getSystemTray().remove(icon);
            icon = null;
        }
    }

    private static BufferedImage iconImage() {
        BufferedImage img = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
        java.awt.Graphics2D g = img.createGraphics();
        g.setColor(new java.awt.Color(23, 26, 33));
        g.fillRoundRect(2, 2, 28, 28, 8, 8);
        g.setColor(new java.awt.Color(59, 130, 246));
        g.fillOval(8, 10, 16, 16);
        g.setColor(java.awt.Color.WHITE);
        g.drawArc(11, 13, 10, 10, 60, 60);
        g.dispose();
        return img;
    }
}