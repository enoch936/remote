package com.company.remoteaccess.server;

import com.company.remoteaccess.core.authentication.ClientIdentity;
import com.company.remoteaccess.core.configuration.AppConfig;
import com.company.remoteaccess.core.state.Role;
import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.networking.NetworkManager;
import com.company.remoteaccess.networking.NetworkManager.NetworkSnapshot;
import com.company.remoteaccess.platform.Elevation;
import com.company.remoteaccess.security.AuditLog;
import com.company.remoteaccess.security.PairingManager;
import com.company.remoteaccess.vpn.VpnException;
import com.company.remoteaccess.vpn.VpnManager;
import com.company.remoteaccess.vpn.VpnStatus;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * The unattended gateway controller (server mode).
 *
 * <p>Behaviour:
 * <ul>
 *   <li>auto-start sequence, including network detection and VPN boot</li>
 *   <li>network-loss detection and safe recovery with exponential backoff +
 *       jitter (no reconnect storms)</li>
 *   <li>watchdog supervision: restarts the tunnel when it becomes unhealthy</li>
 *   <li>clean shutdown restoring temporary networking changes</li>
 * </ul>
 */
public final class GatewayService implements AutoCloseable {

    public interface Listener {
        void onGatewayStateChanged(GatewayState from, GatewayState to);

        void onProgress(String step);
    }

    private final VpnManager vpn;
    private final NetworkManager network;
    private final HealthMonitor health;
    private final ClientRegistry registry;
    private final PairingManager pairingManager;
    private final Supplier<AppConfig> config;
    private final AuditLog audit;
    private final CopyOnWriteArrayList<Listener> listeners = new CopyOnWriteArrayList<>();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean networkOnline = new AtomicBoolean(false);
    private volatile GatewayState state = GatewayState.STOPPED;
    private volatile Thread controllerThread;
    private volatile Thread watchdogThread;
    private BackoffStrategy backoff;
    private volatile int recoveryAttempt;
    private volatile boolean lostWhileOnline;

    // state published to the watchdog
    private final java.util.concurrent.atomic.AtomicReference<VpnStatus> lastStatus =
            new java.util.concurrent.atomic.AtomicReference<>(null);

    public GatewayService(VpnManager vpn, NetworkManager network, HealthMonitor health,
                          ClientRegistry registry, PairingManager pairingManager,
                          Supplier<AppConfig> config) {
        this(vpn, network, health, registry, pairingManager, config, null);
    }

    public GatewayService(VpnManager vpn, NetworkManager network, HealthMonitor health,
                          ClientRegistry registry, PairingManager pairingManager,
                          Supplier<AppConfig> config, AuditLog audit) {
        this.vpn = vpn;
        this.network = network;
        this.health = health;
        this.registry = registry;
        this.pairingManager = pairingManager;
        this.config = config;
        this.audit = audit;
    }

    public void addListener(Listener l) {
        listeners.add(l);
    }

    public GatewayState state() {
        return state;
    }

    public HealthMonitor health() {
        return health;
    }

    public boolean networkOnline() {
        return networkOnline.get();
    }

    // ------------------------------------------------------------------
    // lifecycle
    // ------------------------------------------------------------------

    public void start() {
        if (running.compareAndSet(false, true)) {
            AppConfig cfg = config.get();
            if (cfg.mode() != Role.SERVER) {
                AppLogger.getLogger().warn(LogCategory.SERVER,
                        "gateway start requested in non-server mode");
                return;
            }
            audit("gateway", "start", "mode=server");
            backoff = new BackoffStrategy(cfg.backoffBaseMs() <= 0 ? 2000 : cfg.backoffBaseMs(),
                    60_000, cfg.maxRetries() <= 0 ? 5 : cfg.maxRetries(), 250);
            network.addChangeListener(this::onNetworkChanged);
            controllerThread = new Thread(this::bootstrap, "gateway-controller");
            controllerThread.setDaemon(true);
            controllerThread.start();
            watchdogThread = new Thread(this::watchdog, "gateway-watchdog");
            watchdogThread.setDaemon(true);
            watchdogThread.start();
        }
    }

    private void setState(GatewayState next) {
        GatewayState from = state;
        if (from == next) {
            return;
        }
        state = next;
        if (isAudited(next)) {
            audit("gateway", "state_" + next.name().toLowerCase(), "from=" + from.name().toLowerCase());
        }
        AppLogger.getLogger().info(from.toString(), "gateway state %s -> %s", from, next);
        for (Listener l : listeners) {
            try {
                l.onGatewayStateChanged(from, next);
            } catch (RuntimeException ignored) {
            }
        }
    }

    private void progress(String step) {
        for (Listener l : listeners) {
            try {
                l.onProgress(step);
            } catch (RuntimeException ignored) {
            }
        }
    }

    private void bootstrap() {
        setState(GatewayState.STARTING);
        try {
            // 1. availability of the VPN implementation
            progress("Checking VPN engine");
            if (!Elevation.isElevated()) {
                progress("Administrator privileges required");
                setState(GatewayState.PERMISSION_REQUIRED);
                AppLogger.getLogger().warn(LogCategory.SERVER,
                        "gateway cannot start without administrator privileges");
                return;
            }
            try {
                vpn.adapter().ensureAvailable();
            } catch (VpnException e) {
                setState(GatewayState.BINARIES_MISSING);
                health.recordError(e.getMessage());
                AppLogger.getLogger().error(LogCategory.SERVER, "VPN binaries missing: %s", e.getMessage());
                return;
            }
            recover();
        } catch (Exception e) {
            setState(GatewayState.ERROR);
            health.recordError(e.getMessage());
            AppLogger.getLogger().error(LogCategory.SERVER, e, "gateway bootstrap failed");
        }
    }

    /** Attempt to bring the gateway fully up and set ONLINE. */
    private void recover() {
        setState(GatewayState.RECOVERING);
        try {
            progress("Detecting network");
            NetworkSnapshot snap = network.snapshot();
            boolean online = snap.online();
            networkOnline.set(online);
            if (!online) {
                setState(GatewayState.NETWORK_LOST);
                AppLogger.getLogger().warn(LogCategory.NETWORK,
                        "no active network; waiting for connectivity");
                return;
            }
            progress("Starting VPN gateway");
            List<ClientIdentity> peers = registry.authorized().stream()
                    .map(p -> new ClientIdentity(p.deviceName, p.publicKey, p.vpnAddress))
                    .toList();
            VpnStatus status = vpn.startGateway(peers);
            lastStatus.set(status);
            health.start();
            health.clearError();
            recoveryAttempt = 0;
            setState(GatewayState.ONLINE);
            if (peers.isEmpty()) {
                progress("Gateway online \u2014 no devices paired yet; click \u201cPair a device\u201d");
                AppLogger.getLogger().info(LogCategory.SERVER,
                        "gateway online with no authorized devices; awaiting first pairing");
            } else {
                progress("Gateway online");
                AppLogger.getLogger().info(LogCategory.SERVER,
                        "gateway online with %d authorized device(s)", peers.size());
            }
        } catch (VpnException e) {
            handleRecoveryFailure(e);
        } catch (Exception e) {
            health.recordError(e.getMessage());
            AppLogger.getLogger().error(LogCategory.SERVER, e, "gateway recovery failed");
            setState(GatewayState.ERROR);
        }
    }

    private void handleRecoveryFailure(VpnException e) {
        health.recordError(e.getMessage());
        AppLogger.getLogger().warn(LogCategory.SERVER, "recovery attempt %d failed: %s",
                recoveryAttempt, e.getMessage());
        if (e.kind() == VpnException.Kind.PERMISSION_REQUIRED) {
            setState(GatewayState.PERMISSION_REQUIRED);
            return;
        }
        if (e.kind() == VpnException.Kind.BINARIES_MISSING) {
            setState(GatewayState.BINARIES_MISSING);
            return;
        }
        if (e.kind() == VpnException.Kind.NAT_CONFIGURATION) {
            setState(GatewayState.NAT_FAILED);
            AppLogger.getLogger().error(LogCategory.SERVER, "NAT configuration failed: %s",
                    e.getMessage());
            return;
        }
        if (e.kind() == VpnException.Kind.FIREWALL_CONFIGURATION) {
            setState(GatewayState.FIREWALL_FAILED);
            AppLogger.getLogger().error(LogCategory.SERVER, "firewall configuration failed: %s",
                    e.getMessage());
            return;
        }
        if (recoveryAttempt >= backoff.maxRetries()) {
            setState(GatewayState.ERROR);
            AppLogger.getLogger().error(LogCategory.SERVER,
                    "max recovery attempts reached; manual intervention required");
            return;
        }
        long delay = backoff.nextDelayMs(recoveryAttempt);
        recoveryAttempt++;
        AppLogger.getLogger().info(LogCategory.SERVER,
                "retrying gateway in %d ms (attempt %d)", delay, recoveryAttempt);
        sleepSafely(delay);
        if (running.get()) {
            recover();
        }
    }

    // ------------------------------------------------------------------
    // network change handling
    // ------------------------------------------------------------------

    private void onNetworkChanged(NetworkSnapshot before, NetworkSnapshot after) {
        boolean wasOnline = before == null || before.online();
        boolean isOnline = after == null || after.online();
        if (wasOnline == isOnline) {
            return;
        }
        networkOnline.set(isOnline);
        if (!isOnline) {
            // network lost
            if (state == GatewayState.ONLINE || state == GatewayState.RECOVERING) {
                AppLogger.getLogger().warn(LogCategory.NETWORK, "network lost");
                lostWhileOnline = true;
                setState(GatewayState.NETWORK_LOST);
                // pause the tunnel to avoid black-holing traffic
                try {
                    vpn.stopTunnel();
                } catch (Exception ignored) {
                }
            }
        } else {
            // network restored
            if (lostWhileOnline && running.get() && state == GatewayState.NETWORK_LOST) {
                lostWhileOnline = false;
                AppLogger.getLogger().info(LogCategory.NETWORK, "network restored");
                health.recordReconnect();
                new Thread(this::delayedRecover, "gateway-reconnect").start();
            }
        }
    }

    private void delayedRecover() {
        sleepSafely(500);
        if (running.get()) {
            recover();
        }
    }

    // ------------------------------------------------------------------
    // watchdog
    // ------------------------------------------------------------------

    private void watchdog() {
        while (running.get()) {
            sleepSafely(8000);
            if (!running.get()) {
                return;
            }
            if (state != GatewayState.ONLINE && state != GatewayState.NETWORK_LOST) {
                continue;
            }
            try {
                VpnStatus status = vpn.status();
                lastStatus.set(status);
                boolean netOnline = network.isOnline();
                networkOnline.set(netOnline);
                if (!netOnline) {
                    setState(GatewayState.NETWORK_LOST);
                    continue;
                }
                if (!status.running()) {
                    AppLogger.getLogger().warn(LogCategory.VPN,
                            "watchdog: tunnel not running; recovering");
                    if (chaseRecovery()) {
                        recover();
                    }
                    continue;
                }
                updatePeerPresence(status);
                health.tick(registry.countAuthorized());
            } catch (Exception e) {
                AppLogger.getLogger().warn(LogCategory.SERVER,
                        "watchdog tick failed: %s", e.getMessage());
            }
        }
    }

    private boolean chaseRecovery() {
        int attempts = 0;
        while (attempts < 3 && !vpn.status().running()) {
            attempts++;
            sleepSafely(2000);
        }
        return !vpn.status().running();
    }

    private void updatePeerPresence(VpnStatus status) {
        if (status.peers() == null) {
            return;
        }
        for (var p : status.peers()) {
            if (p.handshaken() && p.latestHandshakeSecondsAgo() < 120) {
                for (String allowed : p.allowedIps()) {
                    String ip = allowed.split("/")[0];
                    registry.findByPublicKey(p.publicKey()).ifPresent(d -> {
                        if (d.vpnAddress.equals(ip)) {
                            registry.markOnline(d.deviceName);
                            registry.persist();
                        }
                    });
                }
                // First confirmed handshake proves key ownership: consume the
                // matching one-time pairing token applied to this peer.
                if (pairingManager != null) {
                    pairingManager.claimForHandshake(p.publicKey());
                }
            }
        }
    }

    @Override
    public void close() {
        AppLogger.getLogger().info(LogCategory.SERVER, "gateway shutdown started");
        audit("gateway", "stop", "clean_shutdown");
        setState(GatewayState.STOPPING);
        running.set(false);
        if (network != null) {
            network.close();
        }
        try {
            vpn.stopTunnel();
        } catch (Exception ignored) {
        }
        vpn.removeAllManagedNetworking();
        vpn.removeAllManagedFirewall();
        vpn.removeAllManagedNat();
        setState(GatewayState.STOPPED);
        AppLogger.getLogger().info(LogCategory.SERVER, "gateway shutdown complete");
    }

    /** Full teardown and fresh bring-up (used by the restart action). */
    public void rebootstrap() {
        new Thread(() -> {
            AppLogger.getLogger().info(LogCategory.SERVER, "gateway rebootstrap requested");
            audit("gateway", "rebootstrap", "requested");
            running.set(false);
            try {
                vpn.stopTunnel();
            } catch (Exception ignored) {
            }
            try {
                vpn.removeAllManagedNetworking();
            } catch (Exception ignored) {
            }
            try {
                vpn.removeAllManagedFirewall();
            } catch (Exception ignored) {
            }
            try {
                vpn.removeAllManagedNat();
            } catch (Exception ignored) {
            }
            setState(GatewayState.STOPPED);
            running.set(true);
            backoff = new BackoffStrategy(
                    config.get().backoffBaseMs() <= 0 ? 2000 : config.get().backoffBaseMs(),
                    60_000,
                    config.get().maxRetries() <= 0 ? 5 : config.get().maxRetries(),
                    250);
            bootstrap();
        }, "gateway-rebootstrap").start();
    }

    private static void sleepSafely(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static boolean isAudited(GatewayState s) {
        return s == GatewayState.ONLINE
                || s == GatewayState.NAT_FAILED
                || s == GatewayState.FIREWALL_FAILED
                || s == GatewayState.PERMISSION_REQUIRED
                || s == GatewayState.BINARIES_MISSING
                || s == GatewayState.ERROR;
    }

    private void audit(String actor, String action, String details) {
        if (audit != null) {
            audit.append(actor, action, details);
        }
    }

    // ------------------------------------------------------------------

    public VpnStatus lastStatus() {
        return lastStatus.get();
    }
}