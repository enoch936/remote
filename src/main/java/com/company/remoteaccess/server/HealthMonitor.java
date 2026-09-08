package com.company.remoteaccess.server;

import com.company.remoteaccess.vpn.VpnStatus;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

/**
 * Periodic health sampling for the server dashboard: uptime, bandwidth, online
 * peers, reconnect counters and the last recorded error/reconnect.
 */
public final class HealthMonitor {

    /** Immutable metrics snapshot. */
    public record Snapshot(long uptimeSeconds,
                           int reconnectCount,
                           String lastReconnectAt,
                           String lastError,
                           int onlinePeers,
                           int authorizedDevices,
                           long rxBytes,
                           long txBytes,
                           long rxRateBps,
                           long txRateBps,
                           boolean networkOnline,
                           boolean vpnHealthy,
                           int stalePeers) {
    }

    private final Supplier<VpnStatus> vpnStatus;
    private final BooleanSupplier networkOnline;
    private final AtomicInteger reconnectCount = new AtomicInteger();
    private final AtomicReference<String> lastReconnectAt = new AtomicReference<>(null);
    private final AtomicReference<String> lastError = new AtomicReference<>(null);
    private final AtomicLong rxBytes = new AtomicLong();
    private final AtomicLong txBytes = new AtomicLong();
    private final AtomicLong rxRate = new AtomicLong();
    private final AtomicLong txRate = new AtomicLong();
    private long prevRx;
    private long prevTx;
    private long prevSampleNanos;
    private volatile long startedAtNanos;
    private volatile boolean started;
    private volatile Snapshot cached = new Snapshot(0, 0, null, null, 0, 0, 0, 0, 0, 0, false, false, 0);

    public HealthMonitor(Supplier<VpnStatus> vpnStatus, BooleanSupplier networkOnline) {
        this.vpnStatus = vpnStatus;
        this.networkOnline = networkOnline;
    }

    public void start() {
        started = true;
        startedAtNanos = System.nanoTime();
    }

    public void recordReconnect() {
        int n = reconnectCount.incrementAndGet();
        lastReconnectAt.set(Instant.now().toString());
        if (n > 100) {
            reconnectCount.set(100);
        }
    }

    public void recordError(String message) {
        if (message != null) {
            lastError.set(message.length() > 300 ? message.substring(0, 300) : message);
        }
    }

    public void clearError() {
        lastError.set(null);
    }

    /** Called by the monitor tick; updates counters and returns a snapshot. */
    public Snapshot tick(int authorizedDevices) {
        VpnStatus vpn = vpnStatus.get();
        long now = System.nanoTime();
        long rx = 0;
        long tx = 0;
        if (vpn != null && vpn.peers() != null) {
            for (var p : vpn.peers()) {
                rx += p.rxBytes();
                tx += p.txBytes();
            }
        }
        if (prevSampleNanos != 0) {
            long elapsed = now - prevSampleNanos;
            if (elapsed > 0) {
                rxRate.set((rx - prevRx) * 1_000_000_000L / elapsed);
                txRate.set((tx - prevTx) * 1_000_000_000L / elapsed);
            }
        }
        prevRx = rx;
        prevTx = tx;
        prevSampleNanos = now;
        rxBytes.set(rx);
        txBytes.set(tx);
        long online = 0;
        long stale = 0;
        if (vpn != null && vpn.running()) {
            for (var p : vpn.peers()) {
                if (p.handshaken() && p.latestHandshakeSecondsAgo() < 120) {
                    online++;
                } else if (p.handshaken()) {
                    stale++;
                }
            }
        }
        long uptime = started && startedAtNanos != 0
                ? (System.nanoTime() - startedAtNanos) / 1_000_000_000L : 0L;
        Snapshot snapshot = new Snapshot(uptime, reconnectCount.get(), lastReconnectAt.get(),
                lastError.get(), (int) online, authorizedDevices,
                rxBytes.get(), txBytes.get(), rxRate.get(), txRate.get(),
                networkOnline.getAsBoolean(), vpn != null && vpn.running(),
                (int) stale);
        cached = snapshot;
        return snapshot;
    }

    /**
     * Returns the last snapshot produced by a background tick. Unlike
     * {@link #tick(int)} this never touches the VPN supplier, so callers on
     * the UI thread can read live stats without spawning subprocesses.
     */
    public Snapshot cached() {
        return cached;
    }
}