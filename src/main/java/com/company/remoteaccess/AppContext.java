package com.company.remoteaccess;

import com.company.remoteaccess.core.configuration.AppConfig;
import com.company.remoteaccess.core.configuration.ConfigException;
import com.company.remoteaccess.core.configuration.ConfigManager;
import com.company.remoteaccess.core.state.Role;
import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.networking.FirewallManager;
import com.company.remoteaccess.networking.NatManager;
import com.company.remoteaccess.networking.NetworkManager;
import com.company.remoteaccess.networking.RoutingManager;
import com.company.remoteaccess.platform.CommandRunner;
import com.company.remoteaccess.security.ConfigCipher;
import com.company.remoteaccess.security.CredentialStore;
import com.company.remoteaccess.security.ConfigIntegrity;
import com.company.remoteaccess.security.Secrets;
import com.company.remoteaccess.vpn.KeyManager;
import com.company.remoteaccess.vpn.VpnAdapter;
import com.company.remoteaccess.vpn.VpnException;
import com.company.remoteaccess.vpn.VpnManager;
import com.company.remoteaccess.vpn.VpnStatus;
import com.company.remoteaccess.vpn.WireGuardAdapter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * Central dependency assembly and shared state for the whole application.
 */
public final class AppContext {

    public final Path baseDir;
    public final Path configFile;
    public final Path dataDir;
    public final Path credentialsDir;
    public final Path vpnDir;
    public final Path logsDir;

    public final CommandRunner runner;
    public final NetworkManager network;
    public final ConfigManager configManager;
    public final CredentialStore credentials;

    private final AtomicReference<AppConfig> config = new AtomicReference<>();
    private volatile VpnManager vpnManager;
    private volatile VpnException vpnBuildError;

    public AppContext(Path baseDir) throws IOException {
        this.baseDir = baseDir;
        this.configFile = baseDir.resolve("config.yaml");
        this.dataDir = baseDir.resolve("data");
        this.credentialsDir = baseDir.resolve("credentials");
        this.vpnDir = baseDir.resolve("vpn");
        this.logsDir = baseDir.resolve("logs");
        for (Path p : java.util.List.of(baseDir, dataDir, credentialsDir, vpnDir, logsDir)) {
            Files.createDirectories(p);
        }
        this.runner = new CommandRunner();
        this.network = new NetworkManager(runner, Duration.ofMillis(3000));
        this.credentials = new CredentialStore(credentialsDir);
        this.credentials.initialize();
        this.configManager = new ConfigManager(configFile,
                ConfigIntegrity.keyFor(credentials), ConfigCipher.keyFor(credentials));
    }

    /** Load persisted configuration (never secrets) or create a default. */
    public AppConfig loadConfig() {
        AppConfig cfg = configManager.load();
        config.set(cfg);
        return cfg;
    }

    public AppConfig config() {
        return config.get();
    }

    public Supplier<AppConfig> configSupplier() {
        return config::get;
    }

    public void updateConfig(AppConfig cfg) throws IOException {
        config.set(cfg);
        configManager.save(cfg);
    }

    /** Replace the in-memory config without writing the file (startup fallback). */
    public void overrideConfig(AppConfig cfg) {
        config.set(cfg);
    }

    public void configureLogging() {
        AppLogger.getLogger().setFile(logsDir.resolve("app.log"));
        logEnvironment();
    }

    private void logEnvironment() {
        AppLogger.getLogger().info(LogCategory.SYSTEM,
                "app home: %s", baseDir.toAbsolutePath());
        AppLogger.getLogger().info(LogCategory.SYSTEM,
                "platform: %s / %s / java %s",
                com.company.remoteaccess.platform.Os.family(),
                System.getProperty("os.arch"), System.getProperty("java.version"));
        AppLogger.getLogger().info(LogCategory.SECURITY,
                "credential store %s", credentialsDir.toAbsolutePath());
    }

    // ------------------------------------------------------------------
    // VPN assembly (lazy: requires WireGuard tooling to be installed)
    // ------------------------------------------------------------------

    /**
     * Never returns {@code null}. When the WireGuard tooling is missing or
     * unusable the returned manager is marked unavailable ({@link
     * VpnManager#isAvailable()} == {@code false}) and all tunnel operations
     * throw a controlled {@link VpnException}(BINARIES_MISSING) instead of a
     * NullPointerException.
     */
    public synchronized VpnManager vpn() {
        if (vpnManager == null) {
            VpnManager assembled = assembleVpnEngine();
            vpnManager = assembled;
        }
        return vpnManager;
    }

    private VpnManager assembleVpnEngine() {
        String wgBin = KeyManager.findWgBinary(runner, config.get().wgBinaryDir())
                .orElse("wg");
        FirewallManager firewall = FirewallManager.forPlatform(runner,
                dataDir.resolve("firewall-rules.json"));
        NatManager nat = NatManager.forPlatform(runner);
        RoutingManager routing = RoutingManager.forPlatform(runner,
                dataDir.resolve("routes.json"));
        KeyManager keyManager = new KeyManager(runner, wgBin);

        VpnAdapter adapter;
        boolean available;
        try {
            adapter = WireGuardAdapter.build(runner, vpnDir, config.get().wgBinaryDir());
            adapter.ensureAvailable();
            vpnBuildError = null;
            available = true;
            AppLogger.getLogger().info(LogCategory.VPN,
                    "VPN engine assembled (wg=%s)", keyManager.binary());
        } catch (VpnException e) {
            vpnBuildError = e;
            adapter = new UnavailableAdapter();
            available = false;
            AppLogger.getLogger().warn(LogCategory.VPN,
                    "VPN engine unavailable: %s", e.getMessage());
        }
        return new VpnManager(adapter, configSupplier(), credentials,
                routing, firewall, nat, keyManager, available);
    }

    public boolean vpnAvailable() {
        VpnManager m = vpnManager;
        return m != null && m.isAvailable();
    }

    public VpnException vpnBuildError() {
        return vpnBuildError;
    }

    public synchronized void rebuildVpnEngine() {
        vpnManager = null;
        vpnBuildError = null;
        vpn();
    }

    /** Re-read configuration from disk (e.g., after the setup wizard ran). */
    public void reloadConfig() {
        loadConfig();
    }

    /**
     * VPN adapter used while WireGuard tooling is unavailable. Every operation
     * reports a controlled {@link VpnException.Kind#BINARIES_MISSING}; status
     * reads report the tunnel as down, so UIs and watchdogs observe a defined
     * state instead of a missing engine.
     */
    private static final class UnavailableAdapter implements VpnAdapter {

        @Override
        public void ensureAvailable() throws VpnException {
            throw missing();
        }

        @Override
        public void writeConfig(String tunnelName, String configText) throws VpnException {
            throw missing();
        }

        @Override
        public void loadConfig(String tunnelName) throws VpnException {
            throw missing();
        }

        @Override
        public void start(String tunnelName) throws VpnException {
            throw missing();
        }

        @Override
        public void stop(String tunnelName) throws VpnException {
            // nothing installed to stop
        }

        @Override
        public void removeConfig(String tunnelName) throws VpnException {
            // nothing installed to remove
        }

        @Override
        public boolean isInstalled(String tunnelName) {
            return false;
        }

        @Override
        public boolean isRunning(String tunnelName) {
            return false;
        }

        @Override
        public VpnStatus status(String tunnelName) {
            return VpnStatus.down(tunnelName);
        }

        private VpnException missing() {
            return new VpnException(VpnException.Kind.BINARIES_MISSING,
                    "WireGuard (wg) is not installed or not on PATH.");
        }
    }
}