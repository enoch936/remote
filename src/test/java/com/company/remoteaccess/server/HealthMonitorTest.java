package com.company.remoteaccess.server;

import com.company.remoteaccess.vpn.VpnPeer;
import com.company.remoteaccess.vpn.VpnStatus;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HealthMonitorTest {

    private static final String PUB = "H".repeat(43) + "=";

    @Test
    void onlineAndStalePeersAreCountedSeparately() {
        VpnStatus vpn = new VpnStatus("company0", true, PUB, 51820, null, List.of(
                new VpnPeer(PUB, "10.50.0.1:51820", List.of("10.50.0.0/24"), 5, 1, 1),
                new VpnPeer("X".repeat(43) + "=", null, List.of("10.50.0.0/24"), 400, 1, 1)));
        HealthMonitor h = new HealthMonitor(() -> vpn, () -> true);
        h.start();

        HealthMonitor.Snapshot snap = h.tick(3);

        assertEquals(1, snap.onlinePeers());
        assertEquals(1, snap.stalePeers());
        assertEquals(3, snap.authorizedDevices());
        assertTrue(snap.vpnHealthy());
        assertTrue(snap.networkOnline());
    }

    @Test
    void stalePeersCountsOldHandshakesOnlyWhileRunning() {
        VpnPeer old = new VpnPeer("Y".repeat(43) + "=", null,
                List.of("10.50.0.0/24"), 900, 1, 1);
        HealthMonitor running = new HealthMonitor(
                () -> new VpnStatus("company0", true, PUB, 51820, null, List.of(old)),
                () -> true);
        running.start();
        assertEquals(1, running.tick(0).stalePeers());

        HealthMonitor stopped = new HealthMonitor(
                () -> VpnStatus.down("company0"), () -> true);
        stopped.start();
        assertEquals(0, stopped.tick(0).stalePeers());
    }

    @Test
    void recordReconnectRollsOverAtOneHundred() {
        HealthMonitor h = new HealthMonitor(() -> VpnStatus.down("company0"), () -> true);
        h.start();
        for (int i = 0; i < 105; i++) {
            h.recordReconnect();
        }
        assertEquals(100, h.tick(0).reconnectCount());
    }

    @Test
    void cachedUsesLastTickWithoutConsultingVpnSupplier() {
        AtomicInteger probes = new AtomicInteger();
        HealthMonitor h = new HealthMonitor(() -> {
            probes.incrementAndGet();
            return VpnStatus.down("company0");
        }, () -> true);
        h.start();

        assertEquals(0, h.cached().onlinePeers());
        assertEquals(0, probes.get());

        HealthMonitor.Snapshot snap = h.tick(2);
        assertEquals(1, probes.get());
        assertEquals(snap, h.cached());
        assertEquals(1, probes.get());
    }

    @Test
    void lastErrorIsTruncated() {
        HealthMonitor h = new HealthMonitor(() -> VpnStatus.down("company0"), () -> true);
        h.start();
        String longError = "x".repeat(1000);
        h.recordError(longError);
        String stored = h.tick(0).lastError();
        assertEquals(300, stored.length());
        h.clearError();
        assertEquals(null, h.tick(0).lastError());
    }
}