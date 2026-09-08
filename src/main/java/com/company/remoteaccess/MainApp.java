package com.company.remoteaccess;

import com.company.remoteaccess.client.ClientService;
import com.company.remoteaccess.client.ReconnectManager;
import com.company.remoteaccess.core.state.ConnectionState;
import com.company.remoteaccess.client.TunnelTester;
import com.company.remoteaccess.core.configuration.AppConfig;
import com.company.remoteaccess.core.configuration.ConfigException;
import com.company.remoteaccess.core.state.Role;
import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.platform.CommandResult;
import com.company.remoteaccess.platform.DataDirs;
import com.company.remoteaccess.platform.DependencyInstaller;
import com.company.remoteaccess.platform.Elevation;
import com.company.remoteaccess.platform.RequirementChecker;
import com.company.remoteaccess.security.AuditLog;
import com.company.remoteaccess.security.PairingManager;
import com.company.remoteaccess.server.ClientRegistry;
import com.company.remoteaccess.server.GatewayService;
import com.company.remoteaccess.server.HealthMonitor;
import com.company.remoteaccess.ui.AppTray;
import com.company.remoteaccess.ui.MainView;
import com.company.remoteaccess.ui.setup.SetupWizard;
import com.company.remoteaccess.vpn.KeyManager;
import com.company.remoteaccess.vpn.VpnManager;
import com.company.remoteaccess.vpn.VpnStatus;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
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
    private PairingManager pairingManager;
    private AuditLog auditLog;

    private volatile boolean serverStarted;
    private final java.util.concurrent.atomic.AtomicBoolean dependencyInstallInProgress =
            new java.util.concurrent.atomic.AtomicBoolean(false);
    private volatile boolean dependencyInstallCancelled;

    @Override
    public void start(Stage stage) {
        Path base = DataDirs.resolveBaseDir();
        try {
            migrateLegacyData(base);
            ctx = new AppContext(base);
        } catch (IOException e) {
            AppLogger.getLogger().error(LogCategory.SYSTEM, e,
                    "application data directory not writable");
            showFatal("Application data directory is not writable: " + base);
            return;
        }
        ctx.configureLogging();
        AppConfig cfg;
        try {
            cfg = ctx.loadConfig();
        } catch (ConfigException e) {
            if (e.kind() == ConfigException.Kind.STALE
                    || e.kind() == ConfigException.Kind.NEWER_VERSION) {
                AppLogger.getLogger().error(LogCategory.SYSTEM, e,
                        "configuration could not be loaded: %s", e.getMessage());
                showFatal("The application configuration could not be loaded.\n\n"
                        + e.getMessage()
                        + "\n\nRestore it from the *.bak file or reset the configuration.");
                return;
            }
            // Invalid/unparseable seat config (e.g. a reset that left a blank client
            // config behind): run the first-run role wizard instead of dying. The
            // file is left untouched until the wizard writes a fresh valid config.
            AppLogger.getLogger().error(LogCategory.SYSTEM, e,
                    "configuration unusable; falling back to the first-run wizard: %s",
                    e.getMessage());
            cfg = AppConfig.create();
            ctx.overrideConfig(cfg);
        }
        role = cfg.mode();

        // An instance launched elevated (auto-elevate relaunch) announces itself so the
        // previous instance closes only once a real elevated window is on screen.
        if (Elevation.isElevated()) {
            Elevation.markStarted();
        }

        logStartupRequirements(cfg);

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

        if (getParameters().getRaw().stream().anyMatch("--fix-requirements"::equals)) {
            applyDependencyFix();
        }
    }

    private boolean isConfigured(AppConfig cfg) {
        boolean clientReady = cfg.mode() == Role.CLIENT
                && cfg.clientPairApplied() && !cfg.clientServerEndpoint().isBlank();
        return AppConfig.isSetupComplete(cfg, clientReady, serverKeysPresent());
    }

    /** A gateway that generated its WireGuard keys counts as a set-up server seat. */
    private boolean serverKeysPresent() {
        try {
            return ctx.credentials.has("server");
        } catch (IOException e) {
            AppLogger.getLogger().warn(LogCategory.SYSTEM,
                    "credential store not readable while deciding setup state: %s", e.getMessage());
            return false;
        }
    }

    /**
     * Start from scratch: wipe config (incl. sidecar + backup), credentials and
     * runtime data, then re-open the first-run role chooser in place.
     */
    public void resetToFirstRun() {
        try {
            if (gatewayService != null) {
                gatewayService.close();
            }
            dependencyInstallCancelled = true;
            wipeState();
            ctx.reloadConfig();
            configureServices(ctx.config());
            mainView.showDashboard();
            showSetupWizard();
            if (tray != null) {
                tray.refresh();
            }
        } catch (Exception e) {
            AppLogger.getLogger().error(LogCategory.SYSTEM, e,
                    "factory reset failed: %s", e.getMessage());
        }
    }

    private void wipeState() throws IOException {
        java.nio.file.Files.deleteIfExists(ctx.configFile);
        java.nio.file.Files.deleteIfExists(com.company.remoteaccess.security.ConfigIntegrity.sidecarFor(ctx.configFile));
        java.nio.file.Files.deleteIfExists(ctx.configFile.resolveSibling(ctx.configFile.getFileName() + ".bak"));
        String integrityFile = com.company.remoteaccess.security.ConfigIntegrity.KEY_CRED + ".secret";
        for (Path dir : java.util.List.of(ctx.credentialsDir, ctx.dataDir)) {
            if (!java.nio.file.Files.isDirectory(dir)) {
                continue;
            }
            try (var stream = java.nio.file.Files.list(dir)) {
                for (Path p : stream.toList()) {
                    if (dir == ctx.credentialsDir && integrityFile.equals(p.getFileName().toString())) {
                        continue; // keep the HMAC key: the current ConfigManager is keyed to it
                    }
                    java.nio.file.Files.deleteIfExists(p);
                }
            }
        }
        ctx.credentials.initialize();
        AppLogger.getLogger().info(LogCategory.SYSTEM,
                "factory reset: configuration, credentials and runtime data cleared");
    }

    /** One-time move of the legacy ~/.company-remote data to the OS-standard dir. */
    private void migrateLegacyData(Path base) throws IOException {
        Path legacy = DataDirs.legacyBaseDir(System.getProperty("user.home"));
        if (DataDirs.requiresMigration(legacy, base)) {
            int moved = DataDirs.migrateLegacy(legacy, base);
            AppLogger.getLogger().info(LogCategory.SYSTEM,
                    "migrated %d data item(s) from %s", moved, legacy);
        }
    }

    private void logStartupRequirements(AppConfig cfg) {
        try {
            var requirements = RequirementChecker.survey(ctx.runner, cfg.wgBinaryDir(),
                    role == Role.SERVER, ctx.configManager.exists());
            for (var r : requirements) {
                if (r.status() != RequirementChecker.Status.OK) {
                    AppLogger.getLogger().warn(LogCategory.SYSTEM,
                            "startup requirement %s (%s): %s", r.id(), r.status(), r.detail());
                } else {
                    AppLogger.getLogger().debug(LogCategory.SYSTEM,
                            "startup requirement %s: ok", r.id());
                }
            }
        } catch (RuntimeException e) {
            AppLogger.getLogger().warn(LogCategory.SYSTEM,
                    "requirement survey failed: %s", e.getMessage());
        }
    }

    /** Build the role-specific services (idempotent; rewired after setup). */
    private void configureServices(AppConfig cfg) {
        role = cfg.mode();
        if (role == Role.CLIENT) {
            VpnManager vpn = ctx.vpn();
            TunnelTester tester = new TunnelTester(new TunnelTester.OsPing(ctx.runner), ctx.network);
            if (clientService == null) {
                clientService = new ClientService(ctx.configSupplier(), ctx.configManager,
                        ctx.credentials, vpn, ctx.network, vpn.routing(), tester);
                reconnect = new ReconnectManager(clientService, ctx.configSupplier());
                reconnect.start();
            }
        } else if (role == Role.SERVER) {
            auditLog = new AuditLog(ctx.dataDir.resolve("audit.log"));
            clientRegistry = new ClientRegistry(ctx.dataDir.resolve("devices.json"), auditLog);
            healthMonitor = new HealthMonitor(() -> statusSupplier(), ctx.network::isOnline);
            VpnManager vpn = ctx.vpn();
            pairingManager = new PairingManager(Duration.ofMinutes(10), auditLog);
            gatewayService = new GatewayService(vpn, ctx.network, healthMonitor, clientRegistry,
                    pairingManager, ctx.configSupplier(), auditLog);
        }
    }

    private VpnStatus statusSupplier() {
        return ctx.vpn().status();
    }

    private void startBackgroundServices() {
        if (role == Role.SERVER && gatewayService != null && !serverStarted) {
            serverStarted = true;
            gatewayService.start();
        } else if (role == Role.CLIENT && clientService != null) {
            AppConfig cfg = ctx.configSupplier().get();
            boolean connected = clientService != null && clientService.state() == ConnectionState.CONNECTED;
            if (cfg.connectOnAppStart() && cfg.clientPairApplied() && !connected) {
                try {
                    clientService.connect();
                } catch (Exception e) {
                    AppLogger.getLogger().error(LogCategory.CLIENT, e,
                            "automatic connect skipped: %s", e.getMessage());
                }
            }
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

    /** Shared server-side pairing manager (also used by the gateway watchdog). */
    public PairingManager pairingManager() {
        return pairingManager;
    }

    /** Server audit trail (tamper-evident action log). Null outside server mode. */
    public AuditLog auditLog() {
        return auditLog;
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

    /** Relaunch this instance elevated (UAC popup on Windows), then exit. */
    public void runAsAdministrator() {
        if (Elevation.isElevated()) {
            return;
        }
        Elevation.clearStartedMarker();
        if (Elevation.relaunchElevated(java.util.List.of())) {
            AppLogger.getLogger().info(LogCategory.SYSTEM, "relaunching elevated for gateway operation");
            awaitElevatedWindow(() -> showFatal(Elevation.requiredHint("manage the gateway")));
        } else {
            showFatal(Elevation.requiredHint("manage the gateway"));
        }
    }

    /**
     * Install missing dependencies (WireGuard). Relaunches elevated with
     * {@code --fix-requirements} when necessary; an already-elevated instance
     * runs the install directly. Single-flight: a second request while an
     * install is already queued or running is coalesced.
     */
    public void installDependencies() {
        if (dependencyInstallInProgress.get()) {
            AppLogger.getLogger().info(LogCategory.SYSTEM,
                    "dependency install already in progress; coalescing duplicate request");
            return;
        }
        if (!Elevation.isElevated()) {
            Elevation.clearStartedMarker();
            if (Elevation.relaunchElevated(java.util.List.of("--fix-requirements"))) {
                AppLogger.getLogger().info(LogCategory.SYSTEM,
                        "relaunching elevated to install dependencies");
                awaitElevatedWindow(() -> showFatal(DependencyInstaller.manualHint()));
            } else {
                showFatal(DependencyInstaller.manualHint());
            }
            return;
        }
        applyDependencyFix();
    }

    /**
     * Keep this window alive until the elevated relaunch really appears (marker
     * written by the elevated instance on startup). If nothing shows up — e.g. the
     * UAC prompt was dismissed — we stay open and let the caller explain instead of
     * disappearing.
     */
    private void awaitElevatedWindow(Runnable onMissing) {
        Thread t = new Thread(() -> {
            long deadline = System.currentTimeMillis() + 30_000;
            boolean started = false;
            while (System.currentTimeMillis() < deadline) {
                if (Elevation.startedMarkerPresent()) {
                    started = true;
                    break;
                }
                try {
                    Thread.sleep(400);
                } catch (InterruptedException e) {
                    return;
                }
            }
            final boolean ok = started;
            Platform.runLater(() -> {
                if (ok) {
                    shutdown();
                } else {
                    onMissing.run();
                }
            });
        }, "await-elevated-window");
        t.setDaemon(true);
        t.start();
    }

    /**
     * Install missing tooling once (single-flight), refresh dependency state,
     * then trigger exactly one gateway rebootstrap when WireGuard is now usable.
     * The gateway is rebound to the freshly assembled engine before the reboot.
     */
    private void applyDependencyFix() {
        if (!dependencyInstallInProgress.compareAndSet(false, true)) {
            AppLogger.getLogger().info(LogCategory.SYSTEM,
                    "dependency install already in progress; coalescing duplicate request");
            return;
        }
        Thread worker = new Thread(() -> {
            try {
                var plan = DependencyInstaller.wireGuardInstallPlan(ctx.runner);
                if (plan.isEmpty()) {
                    AppLogger.getLogger().warn(LogCategory.SYSTEM,
                            "no automatic install plan on this platform; %s",
                            DependencyInstaller.manualHint());
                } else if (!plan.get().automatic()) {
                    AppLogger.getLogger().warn(LogCategory.SYSTEM, "%s", plan.get().label());
                } else {
                    AppLogger.getLogger().info(LogCategory.SYSTEM,
                            "installing dependency: %s", plan.get().label());
                    CommandResult r = ctx.runner.run(plan.get().command(), 180);
                    if (r.success()) {
                        AppLogger.getLogger().info(LogCategory.SYSTEM,
                                "dependency install succeeded: %s", plan.get().label());
                    } else {
                        AppLogger.getLogger().warn(LogCategory.SYSTEM,
                                "dependency install failed (exit %d): %s",
                                r.exitCode(), r.stderr());
                    }
                }
            } finally {
                try {
                    if (dependencyInstallCancelled) {
                        AppLogger.getLogger().info(LogCategory.SYSTEM,
                                "dependency install cancelled by factory reset; skipping rebootstrap");
                        return;
                    }
                    if (KeyManager.findWgBinary(ctx.runner, ctx.config().wgBinaryDir()).isPresent()
                            && gatewayService != null) {
                        AppLogger.getLogger().info(LogCategory.SYSTEM,
                                "WireGuard available after fix; rebooting the gateway");
                        ctx.rebuildVpnEngine();
                        Platform.runLater(() -> {
                            gatewayService.rebindVpn(ctx.vpn());
                            gatewayService.rebootstrap();
                        });
                    }
                } finally {
                    dependencyInstallInProgress.set(false);
                }
            }
        }, "dependency-installer");
        worker.setDaemon(true);
        worker.start();
    }

    /** Graceful application shutdown restoring all temporary changes. */
    public void shutdown() {
        AppLogger.getLogger().info(LogCategory.SYSTEM, "application shutdown");
        if (gatewayService != null) {
            gatewayService.close();
        }
        if (clientService != null) {
            clientService.disconnect();
            clientService.close();
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