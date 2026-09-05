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
import com.company.remoteaccess.security.CredentialStore;
import com.company.remoteaccess.security.Secrets;
import com.company.remoteaccess.vpn.KeyManager;
import com.company.remoteaccess.vpn.VpnException;
import com.company.remoteaccess.vpn.VpnManager;
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
        this.configManager = new ConfigManager(configFile);
        this.credentials = new CredentialStore(credentialsDir);
        this.credentials.initialize();
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

    public synchronized VpnManager vpn() {
        if (vpnManager == null) {
            try {
                WireGuardAdapter adapter = WireGuardAdapter.build(runner, vpnDir,
                        config.get().wgBinaryDir());
                String wgBin = KeyManager.findWgBinary(runner, config.get().wgBinaryDir())
                        .orElse("wg");
                KeyManager keyManager = new KeyManager(runner, wgBin);
                FirewallManager firewall = FirewallManager.forPlatform(runner,
                        dataDir.resolve("firewall-rules.json"));
                NatManager nat = NatManager.forPlatform(runner);
                RoutingManager routing = RoutingManager.forPlatform(runner,
                        dataDir.resolve("routes.json"));
                AppLogger.getLogger().info(LogCategory.VPN,
                        "VPN engine assembled (wg=%s)", keyManager.binary());
                vpnManager = new VpnManager(adapter, configSupplier(), credentials,
                        routing, firewall, nat, keyManager);
                vpnManager.adapter().ensureAvailable();
            } catch (VpnException e) {
                vpnBuildError = e;
                AppLogger.getLogger().warn(LogCategory.VPN,
                        "VPN engine unavailable: %s", e.getMessage());
            }
        }
        return vpnManager;
    }

    public boolean vpnAvailable() {
        return vpnManager != null;
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
}