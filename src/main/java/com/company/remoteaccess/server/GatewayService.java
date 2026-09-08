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
import com.company.remoteaccess.vpn.GatewayVpn;
import com.company.remoteaccess.vpn.VpnException;
import com.company.remoteaccess.vpn.VpnStatus;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

/**
 * The unattended gateway controller (server mode).
 *
 * <p>Lifecycle operations (bootstrap, rebootstrap, recovery, watchdog
 * supervision, network-change handling, tunnel teardown) are serialized through
 * a single-threaded lifecycle executor, so concurrent triggers can never mutate
 * gateway state at the same time. A generation token invalidates stale
 * asynchronous work: any recovery/bootstrap captured under an older generation
 * exits before touching state once a newer operation ({@link #rebootstrap()},
 * {@link #close()}) has begun.
 *
 * <ul>
 *   <li>single-flight rebootstrap and recovery (duplicates coalesced)</li>
 *   <li>validated state transitions; recovery cannot loop forever after the
 *       maximum attempt count has been reached</li>
 *   <li>watchdog supervision: restarts the tunnel when it becomes unhealthy</li>
 *   <li>clean shutdown restoring temporary networking changes</li>
 * </ul>
 */
public final class GatewayService implements AutoCloseable {

    public interface Listener {
        void onGatewayStateChanged(GatewayState from, GatewayState to);

        void onProgress(String step);
    }

    private static final long WATCHDOG_INTERVAL_MS = 8_000;
    private static final long NETWORK_RECOVER_DELAY_MS = 500;

    private volatile GatewayVpn vpn;
    private final NetworkManager network;
    private final HealthMonitor health;
    private final ClientRegistry registry;
    private final PairingManager pairingManager;
    private final Supplier<AppConfig> config;
    private final AuditLog audit;
    private final BooleanSupplier isElevated;
    private final CopyOnWriteArrayList<Listener> listeners = new CopyOnWriteArrayList<>();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicBoolean networkOnline = new AtomicBoolean(false);
    private final AtomicBoolean bootstrapPending = new AtomicBoolean(false);
    private final AtomicBoolean recoveryPending = new AtomicBoolean(false);
    private final AtomicBoolean recoveryExhausted = new AtomicBoolean(false);
    private final AtomicLong generation = new AtomicLong(0);
    private final AtomicReference<VpnStatus> lastStatus = new AtomicReference<>(null);

    private volatile GatewayState state = GatewayState.STOPPED;
    private volatile ExecutorService lifecycle;
    private volatile ScheduledExecutorService scheduler;
    private volatile boolean lostWhileOnline;
    private BackoffStrategy backoff;
    private volatile int recoveryAttempt;

    public GatewayService(GatewayVpn vpn, NetworkManager network, HealthMonitor health,
                          ClientRegistry registry, PairingManager pairingManager,
                          Supplier<AppConfig> config) {
        this(vpn, network, health, registry, pairingManager, config, null);
    }

    public GatewayService(GatewayVpn vpn, NetworkManager network, HealthMonitor health,
                          ClientRegistry registry, PairingManager pairingManager,
                          Supplier<AppConfig> config, AuditLog audit) {
        this(vpn, network, health, registry, pairingManager, config, audit, Elevation::isElevated);
    }

    /** Package-visible seam so tests can stub the elevation probe. */
    GatewayService(GatewayVpn vpn, NetworkManager network, HealthMonitor health,
                   ClientRegistry registry, PairingManager pairingManager,
                   Supplier<AppConfig> config, AuditLog audit, BooleanSupplier isElevated) {
        this.vpn = vpn;
        this.network = network;
        this.health = health;
        this.registry = registry;
        this.pairingManager = pairingManager;
        this.config = config;
        this.audit = audit;
        this.isElevated = isElevated == null ? Elevation::isElevated : isElevated;
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

    public VpnStatus lastStatus() {
        return lastStatus.get();
    }

    /**
     * Re-point the gateway at a (re)built VPN engine, e.g. after WireGuard was
     * installed. The volatile reference is picked up by the next lifecycle task,
     * so the swap stays serialized with any in-flight operation.
     */
    public void rebindVpn(GatewayVpn freshVpn) {
        this.vpn = freshVpn;
        AppLogger.getLogger().info(LogCategory.SERVER, "gateway VPN engine rebound");
    }

    // ------------------------------------------------------------------
    // lifecycle
    // ------------------------------------------------------------------

    public void start() {
        if (closed.get() || !running.compareAndSet(false, true)) {
            return;
        }
        AppConfig cfg = config.get();
        if (cfg.mode() != Role.SERVER) {
            AppLogger.getLogger().warn(LogCategory.SERVER,
                    "gateway start requested in non-server mode");
            running.set(false);
            return;
        }
        audit("gateway", "start", "mode=server");
        resetBackoff(cfg);
        recoveryAttempt = 0;
        recoveryExhausted.set(false);
        network.addChangeListener(this::onNetworkChanged);
        ensureLifecycle();
        ensureScheduler();
        scheduleWatchdog();
        lifecycleSubmit("gateway bootstrap", () -> doBootstrap(generation.get()));
    }

    /**
     * Full teardown and fresh bring-up (restart action, or after a dependency
     * install). Single-flight: duplicate requests while one bootstrap is queued
     * or running are coalesced.
     */
    public void rebootstrap() {
        if (!running.get() || closed.get()) {
            AppLogger.getLogger().info(LogCategory.SERVER,
                    "gateway rebootstrap requested while stopped; ignored");
            return;
        }
        if (!bootstrapPending.compareAndSet(false, true)) {
            AppLogger.getLogger().info(LogCategory.SERVER,
                    "Gateway rebootstrap already in progress; coalescing duplicate request");
            return;
        }
        audit("gateway", "rebootstrap", "requested");
        generation.incrementAndGet();
        recoveryExhausted.set(false);
        recoveryAttempt = 0;
        lifecycleSubmit("gateway rebootstrap", () -> {
            try {
                doRebootstrap(generation.get());
            } finally {
                bootstrapPending.set(false);
            }
        });
    }

    /**
     * Public retry entry point for explicit UI/manual retries. Clears the
     * exhaustion flag so an operator action can always start a fresh recovery.
     */
    public void requestRecovery() {
        if (!running.get() || closed.get()) {
            return;
        }
        recoveryExhausted.set(false);
        recoveryAttempt = 0;
        requestRecovery("explicit-retry");
    }

    private void doRebootstrap(long epoch) {
        if (epoch != generation.get()) {
            return;
        }
        AppLogger.getLogger().info(LogCategory.SERVER, "gateway rebootstrap started");
        setState(GatewayState.STOPPED);
        stopTunnelQuietly();
        teardownManagedNetworkState();
        resetBackoff(config.get());
        doBootstrap(epoch);
    }

    private void doBootstrap(long epoch) {
        if (epoch != generation.get()) {
            return;
        }
        if (!setState(GatewayState.STARTING)) {
            return;
        }
        try {
            progress("Checking VPN engine");
            GatewayVpn current = vpn;
            if (current == null || !current.isAvailable()) {
                health.recordError("WireGuard (wg) is not installed or not on PATH.");
                setState(GatewayState.BINARIES_MISSING);
                AppLogger.getLogger().warn(LogCategory.SERVER,
                        "VPN engine unavailable; gateway cannot bootstrap");
                return;
            }
            if (!isElevated.getAsBoolean()) {
                progress("Administrator privileges required");
                setState(GatewayState.PERMISSION_REQUIRED);
                AppLogger.getLogger().warn(LogCategory.SERVER,
                        "gateway cannot start without administrator privileges");
                return;
            }
            doRecover(epoch);
        } catch (Exception e) {
            setState(GatewayState.ERROR);
            health.recordError(e.getMessage());
            AppLogger.getLogger().error(LogCategory.SERVER, e, "gateway bootstrap failed");
        }
    }

    /** Bring the gateway fully up. Serialized + single-flight; honors epoch. */
    private void doRecover(long epoch) {
        if (epoch != generation.get()) {
            return;
        }
        if (closed.get() || !running.get()) {
            return;
        }
        if (recoveryExhausted.get()) {
            setState(GatewayState.ERROR);
            AppLogger.getLogger().warn(LogCategory.SERVER,
                    "recovery exhausted after max attempts; manual retry required");
            return;
        }
        if (!recoveryPending.compareAndSet(false, true)) {
            AppLogger.getLogger().info(LogCategory.SERVER,
                    "Recovery already in progress; ignoring duplicate recovery request");
            return;
        }
        try {
            // Error is terminal for automated recovery; only an explicit operator
            // retry reaches doRecover from ERROR, so unwind it through STARTING
            // before re-entering the normal recovery sequence.
            if (state == GatewayState.ERROR) {
                setState(GatewayState.STARTING);
            }
            if (!setState(GatewayState.RECOVERING)) {
                return;
            }
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
            handleRecoveryFailure(epoch, e);
        } catch (Exception e) {
            health.recordError(e.getMessage());
            AppLogger.getLogger().error(LogCategory.SERVER, e, "gateway recovery failed");
            setState(GatewayState.ERROR);
        } finally {
            recoveryPending.set(false);
        }
    }

    private void handleRecoveryFailure(long epoch, VpnException e) {
        health.recordError(e.getMessage());
        AppLogger.getLogger().warn(LogCategory.SERVER, "recovery attempt %d failed: %s",
                recoveryAttempt, e.getMessage());
        switch (e.kind()) {
            case PERMISSION_REQUIRED -> {
                setState(GatewayState.PERMISSION_REQUIRED);
                return;
            }
            case BINARIES_MISSING -> {
                setState(GatewayState.BINARIES_MISSING);
                return;
            }
            case NAT_CONFIGURATION -> {
                setState(GatewayState.NAT_FAILED);
                AppLogger.getLogger().error(LogCategory.SERVER,
                        "NAT configuration failed: %s", e.getMessage());
                return;
            }
            case FIREWALL_CONFIGURATION -> {
                setState(GatewayState.FIREWALL_FAILED);
                AppLogger.getLogger().error(LogCategory.SERVER,
                        "firewall configuration failed: %s", e.getMessage());
                return;
            }
            default -> {
            }
        }
        if (recoveryAttempt >= backoff.maxRetries()) {
            recoveryExhausted.set(true);
            setState(GatewayState.ERROR);
            AppLogger.getLogger().error(LogCategory.SERVER,
                    "max recovery attempts reached; manual intervention required "
                            + "(state stays %s until an explicit retry)", GatewayState.ERROR);
            return;
        }
        int attempt = recoveryAttempt;
        recoveryAttempt++;
        long delay = backoff.nextDelayMs(attempt);
        if (delay < 0) {
            recoveryExhausted.set(true);
            setState(GatewayState.ERROR);
            AppLogger.getLogger().error(LogCategory.SERVER,
                    "max recovery attempts reached; manual intervention required");
            return;
        }
        AppLogger.getLogger().info(LogCategory.SERVER,
                "retrying gateway in %d ms (attempt %d/%d)", delay, attempt + 1,
                backoff.maxRetries());
        scheduleRetry(epoch, delay);
    }

    private void scheduleRetry(long epoch, long delayMs) {
        ScheduledExecutorService sched = scheduler;
        if (sched == null || sched.isShutdown()) {
            return;
        }
        sched.schedule(() -> {
            if (closed.get() || !running.get()) {
                return;
            }
            lifecycleSubmit("gateway recovery retry", () -> doRecover(epoch));
        }, delayMs, TimeUnit.MILLISECONDS);
    }

    /** Single-flight async recovery trigger (watchdog, network restore, manual). */
    private void requestRecovery(String reason) {
        if (!running.get() || closed.get()) {
            return;
        }
        if (recoveryExhausted.get()) {
            AppLogger.getLogger().warn(LogCategory.SERVER,
                    "recovery exhausted; ignoring recovery request (%s); manual retry required", reason);
            return;
        }
        if (recoveryPending.get()) {
            AppLogger.getLogger().info(LogCategory.SERVER,
                    "Recovery already in progress; ignoring duplicate recovery request (%s)", reason);
            return;
        }
        lifecycleSubmit("gateway recovery", () -> doRecover(generation.get()));
    }

    // ------------------------------------------------------------------
    // watchdog
    // ------------------------------------------------------------------

    private void scheduleWatchdog() {
        ScheduledExecutorService sched = scheduler;
        if (sched == null || sched.isShutdown()) {
            return;
        }
        sched.scheduleWithFixedDelay(() -> {
            if (closed.get() || !running.get()) {
                return;
            }
            lifecycleSubmit("gateway watchdog tick", this::watchdogTick);
        }, WATCHDOG_INTERVAL_MS, WATCHDOG_INTERVAL_MS, TimeUnit.MILLISECONDS);
    }

    private void watchdogTick() {
        if (closed.get() || !running.get()) {
            return;
        }
        GatewayState s = state;
        if (s != GatewayState.ONLINE && s != GatewayState.NETWORK_LOST) {
            return;
        }
        try {
            VpnStatus status = vpn.status();
            lastStatus.set(status);
            boolean netOnline = network.isOnline();
            networkOnline.set(netOnline);
            if (!netOnline) {
                setState(GatewayState.NETWORK_LOST);
                return;
            }
            if (!status.running()) {
                AppLogger.getLogger().warn(LogCategory.VPN,
                        "watchdog: tunnel not running; recovering");
                if (recoveryExhausted.get()) {
                    setState(GatewayState.ERROR);
                    AppLogger.getLogger().warn(LogCategory.SERVER,
                            "watchdog: recovery exhausted; remaining in %s until an explicit retry",
                            GatewayState.ERROR);
                    return;
                }
                requestRecovery("watchdog");
                return;
            }
            updatePeerPresence(status);
            health.tick(registry.countAuthorized());
        } catch (Exception e) {
            AppLogger.getLogger().warn(LogCategory.SERVER,
                    "watchdog tick failed: %s", safeMessage(e));
        }
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

    // ------------------------------------------------------------------
    // network change handling (always serialized onto the lifecycle thread)
    // ------------------------------------------------------------------

    private void onNetworkChanged(NetworkSnapshot before, NetworkSnapshot after) {
        boolean wasOnline = before == null || before.online();
        boolean isOnline = after == null || after.online();
        if (wasOnline == isOnline) {
            return;
        }
        networkOnline.set(isOnline);
        lifecycleSubmit("network change", () -> handleNetworkTransition(isOnline));
    }

    private void handleNetworkTransition(boolean isOnline) {
        if (!isOnline) {
            if (state == GatewayState.ONLINE || state == GatewayState.RECOVERING) {
                AppLogger.getLogger().warn(LogCategory.NETWORK, "network lost");
                lostWhileOnline = true;
                setState(GatewayState.NETWORK_LOST);
                // pause the tunnel to avoid black-holing traffic
                stopTunnelQuietly();
            }
        } else {
            if (lostWhileOnline && running.get() && state == GatewayState.NETWORK_LOST) {
                lostWhileOnline = false;
                AppLogger.getLogger().info(LogCategory.NETWORK, "network restored");
                health.recordReconnect();
                scheduleRecover(NETWORK_RECOVER_DELAY_MS, "network-restored");
            }
        }
    }

    private void scheduleRecover(long delayMs, String reason) {
        ScheduledExecutorService sched = scheduler;
        if (sched == null || sched.isShutdown()) {
            return;
        }
        sched.schedule(() -> {
            if (closed.get() || !running.get()) {
                return;
            }
            requestRecovery(reason);
        }, delayMs, TimeUnit.MILLISECONDS);
    }

    // ------------------------------------------------------------------
    // serialized execution helpers
    // ------------------------------------------------------------------

    private void ensureLifecycle() {
        if (lifecycle == null || lifecycle.isShutdown()) {
            lifecycle = Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "gateway-lifecycle");
                t.setDaemon(true);
                return t;
            });
        }
    }

    private void lifecycleSubmit(String label, Runnable task) {
        ExecutorService ex = lifecycle;
        if (ex == null || ex.isShutdown() || closed.get() || !running.get()) {
            AppLogger.getLogger().debug(LogCategory.SERVER,
                    "lifecycle task '%s' skipped (gateway not running)", label);
            return;
        }
        try {
            ex.execute(() -> {
                try {
                    AppLogger.getLogger().debug(LogCategory.SERVER, "lifecycle: %s", label);
                    task.run();
                } catch (Exception e) {
                    AppLogger.getLogger().error(LogCategory.SERVER, e,
                            "lifecycle task failed: %s", safeMessage(e));
                }
            });
        } catch (RejectedExecutionException e) {
            AppLogger.getLogger().debug(LogCategory.SERVER,
                    "lifecycle task '%s' rejected (executor shutting down)", label);
        }
    }

    private void stopTunnelQuietly() {
        try {
            vpn.stopTunnel();
        } catch (Exception ignored) {
        }
    }

    private void teardownManagedNetworkState() {
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
    }

    // ------------------------------------------------------------------
    // state machine
    // ------------------------------------------------------------------

    /** Enforce the transition table; refuse illegal moves (such as a fresh
     *  automated recovery after the failure budget is exhausted). */
    private boolean setState(GatewayState next) {
        GatewayState from = state;
        if (from == next) {
            return true;
        }
        if (!canTransition(from, next)) {
            AppLogger.getLogger().warn(LogCategory.SERVER,
                    "illegal gateway state transition %s -> %s ignored", from, next);
            return false;
        }
        state = next;
        if (isAudited(next)) {
            audit("gateway", "state_" + next.name().toLowerCase(), "from=" + from.name().toLowerCase());
        }
        AppLogger.getLogger().info(LogCategory.SERVER, "gateway state %s -> %s", from, next);
        for (Listener l : listeners) {
            try {
                l.onGatewayStateChanged(from, next);
            } catch (RuntimeException ignored) {
            }
        }
        return true;
    }

    static boolean canTransition(GatewayState from, GatewayState to) {
        if (from == to) {
            return true;
        }
        if (to == GatewayState.STOPPED) {
            // STOPPING -> STOPPED is the normal teardown; any other live state can
            // also be force-reset to STOPPED by rebootstrap/close.
            return from == GatewayState.STOPPING || from != GatewayState.STOPPED;
        }
        return switch (from) {
            case STOPPED -> to == GatewayState.STARTING || to == GatewayState.STOPPING;
            case STARTING -> to == GatewayState.ONLINE
                    || to == GatewayState.RECOVERING
                    || to == GatewayState.NETWORK_LOST
                    || to == GatewayState.BINARIES_MISSING
                    || to == GatewayState.PERMISSION_REQUIRED
                    || to == GatewayState.NAT_FAILED
                    || to == GatewayState.FIREWALL_FAILED
                    || to == GatewayState.ERROR
                    || to == GatewayState.STOPPING;
            case RECOVERING -> to == GatewayState.ONLINE
                    || to == GatewayState.NETWORK_LOST
                    || to == GatewayState.BINARIES_MISSING
                    || to == GatewayState.PERMISSION_REQUIRED
                    || to == GatewayState.NAT_FAILED
                    || to == GatewayState.FIREWALL_FAILED
                    || to == GatewayState.ERROR
                    || to == GatewayState.STOPPING;
            case ONLINE -> to == GatewayState.RECOVERING
                    || to == GatewayState.NETWORK_LOST
                    || to == GatewayState.ERROR
                    || to == GatewayState.STOPPING;
            case NETWORK_LOST -> to == GatewayState.RECOVERING
                    || to == GatewayState.ERROR
                    || to == GatewayState.STOPPING;
            case BINARIES_MISSING -> to == GatewayState.STARTING
                    || to == GatewayState.ERROR
                    || to == GatewayState.STOPPING;
            case PERMISSION_REQUIRED -> to == GatewayState.STARTING
                    || to == GatewayState.ERROR
                    || to == GatewayState.STOPPING;
            case NAT_FAILED -> to == GatewayState.STARTING
                    || to == GatewayState.ERROR
                    || to == GatewayState.STOPPING;
            case FIREWALL_FAILED -> to == GatewayState.STARTING
                    || to == GatewayState.ERROR
                    || to == GatewayState.STOPPING;
            case ERROR -> to == GatewayState.STARTING
                    || to == GatewayState.STOPPING;
            case STOPPING -> to == GatewayState.STOPPED;
        };
    }

    private void progress(String step) {
        for (Listener l : listeners) {
            try {
                l.onProgress(step);
            } catch (RuntimeException ignored) {
            }
        }
    }

    // ------------------------------------------------------------------
    // shutdown / wiring
    // ------------------------------------------------------------------

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        AppLogger.getLogger().info(LogCategory.SERVER, "gateway shutdown started");
        audit("gateway", "stop", "clean_shutdown");
        setState(GatewayState.STOPPING);
        generation.incrementAndGet();
        running.set(false);
        networkOnline.set(false);
        ScheduledExecutorService sched = scheduler;
        scheduler = null;
        if (sched != null) {
            sched.shutdownNow();
        }
        ExecutorService ex = lifecycle;
        lifecycle = null;
        if (ex != null) {
            ex.shutdownNow();
        }
        if (network != null) {
            network.close();
        }
        stopTunnelQuietly();
        teardownManagedNetworkState();
        setState(GatewayState.STOPPED);
        AppLogger.getLogger().info(LogCategory.SERVER, "gateway shutdown complete");
    }

    private void ensureScheduler() {
        if (scheduler == null || scheduler.isShutdown()) {
            scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "gateway-scheduler");
                t.setDaemon(true);
                return t;
            });
        }
    }

    private void resetBackoff(AppConfig cfg) {
        backoff = new BackoffStrategy(cfg.backoffBaseMs() <= 0 ? 2000 : cfg.backoffBaseMs(),
                60_000, cfg.maxRetries() <= 0 ? 5 : cfg.maxRetries(), 250);
    }

    private static boolean isAudited(GatewayState s) {
        return s == GatewayState.ONLINE
                || s == GatewayState.NAT_FAILED
                || s == GatewayState.FIREWALL_FAILED
                || s == GatewayState.PERMISSION_REQUIRED
                || s == GatewayState.BINARIES_MISSING
                || s == GatewayState.ERROR;
    }

    private static String safeMessage(Throwable t) {
        String m = t == null ? null : t.getMessage();
        return m == null || m.isBlank() ? t.getClass().getSimpleName() : m;
    }

    private void audit(String actor, String action, String details) {
        if (audit != null) {
            audit.append(actor, action, details);
        }
    }
}