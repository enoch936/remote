package com.company.remoteaccess;

import com.company.remoteaccess.client.ClientService;
import com.company.remoteaccess.client.ReconnectManager;
import com.company.remoteaccess.client.TunnelTester;
import com.company.remoteaccess.core.configuration.AppConfig;
import com.company.remoteaccess.core.state.Role;
import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.server.ClientRegistry;
import com.company.remoteaccess.server.GatewayService;
import com.company.remoteaccess.server.HealthMonitor;
import com.company.remoteaccess.ui.AppTray;
import com.company.remoteaccess.ui.MainView;
import com.company.remoteaccess.ui.setup.SetupWizard;
import com.company.remoteaccess.vpn.VpnManager;
import com.company.remoteaccess.vpn.VpnStatus;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;
import java.nio.file.Path;
import java.util.function.Supplier;

/**
 * Application entry: loads context, decides between the setup wizard and the
 * role dashboard, and starts background services.
 */
public final class MainApp extends Application {

    private AppContext ctx;
    private Role role;
    private MainView mainView;
    private AppTray tray;

    private ClientService clientService;
    private ReconnectManager reconnect;
    private ClientRegistry clientRegistry;
    private HealthMonitor healthMonitor;
    private GatewayService gatewayService;

    private volatile boolean serverStarted;

    @Override
    public void start(Stage stage) {
        Path base = Path.of(System.getProperty("user.home"), ".company-remote");
        try {
            ctx = new AppContext(base);
        } catch (IOException e) {
            AppLogger.getLogger().error(LogCategory.SYSTEM, e,
                    "application data directory not writable");
            showFatal("Application data directory is not writable: " + base);
            return;
        }
        ctx.configureLogging();
        AppConfig cfg = ctx.loadConfig();
        role = cfg.mode();

        configureServices(cfg);

        mainView = new MainView(this);
        Scene scene = new Scene(mainView.root(), 1000, 660);
        scene.getStylesheets().add(getClass().getResource("/styles.css").toExternalForm());
        stage.setTitle(BuildInfo.name());
        stage.setScene(scene);
        stage.setMinWidth(760);
        stage.setMinHeight(520);
        stage.setOnCloseRequest(e -> {
            e.consume();
            hideToTray();
        });
        stage.show();

        installTray();
        ctx.network.startMonitor();

        boolean configured = isConfigured(cfg);
        applyTheme(cfg.theme());
        if (!configured) {
            showSetupWizard();
        } else {
            mainView.showDashboard();
            startBackgroundServices();
        }
    }

    private boolean isConfigured(AppConfig cfg) {
        if (ctx.configManager.exists()) {
            return true;
        }
        if (cfg.mode() == Role.CLIENT) {
            try {
                return clientService != null && clientService.isRegistered();
            } catch (IOException e) {
                return false;
            }
        }
        return false;
    }

    /** Build the role-specific services (idempotent; rewired after setup). */
    private void configureServices(AppConfig cfg) {
        role = cfg.mode();
        if (role == Role.CLIENT) {
            VpnManager vpn = ctx.vpn();
            TunnelTester tester = new TunnelTester(new TunnelTester.OsPing(ctx.runner), ctx.network);
            if (clientService == null) {
                clientService = new ClientService(ctx.configSupplier(), ctx.configManager,
                        ctx.credentials, vpn, ctx.network,
                        vpn == null ? null : vpn.routing(), tester);
                reconnect = new ReconnectManager(clientService, ctx.configSupplier());
                reconnect.start();
            }
        } else if (role == Role.SERVER) {
            clientRegistry = new ClientRegistry(ctx.baseDir.resolve("data" + "/devices.json"));
            healthMonitor = new HealthMonitor(() -> statusSupplier(), ctx.network::isOnline);
            VpnManager vpn = ctx.vpn();
            gatewayService = new GatewayService(vpn, ctx.network, healthMonitor, clientRegistry,
                    ctx.configSupplier());
        }
    }

    private VpnStatus statusSupplier() {
        VpnManager vpn = ctx.vpn();
        return vpn == null ? VpnStatus.down("company0") : vpn.status();
    }

    private void startBackgroundServices() {
        if (role == Role.SERVER && gatewayService != null && !serverStarted) {
            serverStarted = true;
            gatewayService.start();
        }
    }

    public AppContext context() {
        return ctx;
    }

    public Role role() {
        return role;
    }

    public MainView mainView() {
        return mainView;
    }

    public ClientService clientService() {
        return clientService;
    }

    public ReconnectManager reconnect() {
        return reconnect;
    }

    public ClientRegistry clientRegistry() {
        return clientRegistry;
    }

    public HealthMonitor healthMonitor() {
        return healthMonitor;
    }

    public GatewayService gatewayService() {
        return gatewayService;
    }

    public void applyTheme(String theme) {
        mainView.applyTheme("dark".equalsIgnoreCase(theme) ? "dark" : "light");
    }

    // ------------------------------------------------------------------
    // setup wizard
    // ------------------------------------------------------------------

    public void showSetupWizard() {
        Platform.runLater(() -> {
            SetupWizard wizard = new SetupWizard(this);
            wizard.show(primaryStage());
            wizard.onComplete(completedCfg -> {
                try {
                    ctx.updateConfig(completedCfg);
                } catch (Exception e) {
                    AppLogger.getLogger().error(LogCategory.SYSTEM, e, "config save after setup failed");
                }
                ctx.rebuildVpnEngine();
                ctx.reloadConfig();
                configureServices(ctx.config());
                applyTheme(ctx.config().theme());
                mainView.showDashboard();
                startBackgroundServices();
                if (tray != null) {
                    tray.refresh();
                }
            });
        });
    }

    private Stage primaryStage() {
        return (Stage) mainView.root().getScene().getWindow();
    }

    // ------------------------------------------------------------------
    // tray
    // ------------------------------------------------------------------

    private void installTray() {
        try {
            tray = new AppTray(this);
            tray.install();
        } catch (Exception e) {
            AppLogger.getLogger().warn(LogCategory.UI,
                    "system tray unavailable: %s", e.getMessage());
        }
    }

    public void hideToTray() {
        Stage s = primaryStage();
        if (s != null && tray != null && tray.installed()) {
            s.hide();
        } else {
            shutdown();
        }
    }

    public void showWindow() {
        Platform.runLater(() -> {
            Stage s = primaryStage();
            if (s != null) {
                s.show();
                s.toFront();
            }
        });
    }

    /** Graceful application shutdown restoring all temporary changes. */
    public void shutdown() {
        AppLogger.getLogger().info(LogCategory.SYSTEM, "application shutdown");
        if (gatewayService != null) {
            gatewayService.close();
        }
        if (clientService != null) {
            clientService.disconnect();
        }
        if (reconnect != null) {
            reconnect.close();
        }
        if (tray != null) {
            tray.shutdown();
        }
        if (ctx.network != null) {
            ctx.network.close();
        }
        Platform.exit();
        System.exit(0);
    }

    private void showFatal(String message) {
        javafx.scene.control.Alert alert = new javafx.scene.control.Alert(
                javafx.scene.control.Alert.AlertType.ERROR);
        alert.setTitle(BuildInfo.name());
        alert.setHeaderText("Unable to start");
        alert.setContentText(message);
        alert.showAndWait();
        Platform.exit();
    }
}