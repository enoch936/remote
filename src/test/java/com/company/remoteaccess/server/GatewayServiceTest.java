package com.company.remoteaccess.server;

import com.company.remoteaccess.core.authentication.ClientIdentity;
import com.company.remoteaccess.core.configuration.AppConfig;
import com.company.remoteaccess.networking.NetworkManager;
import com.company.remoteaccess.networking.NetworkManager.NetworkSnapshot;
import com.company.remoteaccess.platform.CommandRunner;
import com.company.remoteaccess.vpn.GatewayVpn;
import com.company.remoteaccess.vpn.VpnException;
import com.company.remoteaccess.vpn.VpnStatus;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * GatewayService lifecycle/concurrency regressions. Everything VPN/network is a
 * deterministic fake, so these tests run without OS-level commands or elevation.
 */
class GatewayServiceTest {

    private static final long AWAIT_MS = 8_000;

    /** Deterministic NetworkManager double. */
    static class FakeNetwork extends NetworkManager {
        final boolean online;

        FakeNetwork(boolean online) {
            super(new CommandRunner(), null);
            this.online = online;
        }

        @Override
        public NetworkSnapshot snapshot() {
            return new NetworkSnapshot(List.of(), online);
        }

        @Override
        public boolean isOnline() {
            return online;
        }

        @Override
        public void addChangeListener(ChangeListener l) {
        }

        @Override
        public void close() {
        }
    }

    /** Deterministic GatewayVpn double with call accounting. */
    static class FakeGatewayVpn implements GatewayVpn {
        final boolean available;
        final AtomicInteger startGatewayCalls = new AtomicInteger();
        final VpnStatus startResult;
        final VpnException startError;
        volatile VpnStatus current;

        FakeGatewayVpn(boolean available, VpnStatus startResult, VpnException startError) {
            this.available = available;
            this.startResult = startResult;
            this.startError = startError;
            this.current = VpnStatus.down("company0");
        }

        @Override
        public boolean isAvailable() {
            return available;
        }

        @Override
        public VpnStatus startGateway(List<ClientIdentity> authorizedPeers) throws VpnException {
            startGatewayCalls.incrementAndGet();
            if (startError != null) {
                throw startError;
            }
            current = startResult;
            return startResult;
        }

        @Override
        public VpnStatus stopTunnel() {
            current = VpnStatus.down("company0");
            return current;
        }

        @Override
        public VpnStatus status() {
            return current;
        }

        @Override
        public void addPeerToRunning(String publicKey, String vpnAddress) {
        }

        @Override
        public void removeAllManagedNetworking() {
        }

        @Override
        public void removeAllManagedFirewall() {
        }

        @Override
        public void removeAllManagedNat() {
        }
    }

    private static AppConfig serverConfig(int maxRetries, int backoffBaseMs) {
        return AppConfig.create()
                .with("mode", "SERVER")
                .withSection("security", java.util.Map.of(
                        "autoReconnect", true,
                        "maxRetries", maxRetries,
                        "backoffBaseMs", backoffBaseMs,
                        "connectOnAppStart", true));
    }

    private GatewayService gateway(GatewayVpn vpn, AppConfig cfg, boolean elevated, boolean networkOnline) {
        ClientRegistry registry = new ClientRegistry(null);
        HealthMonitor health = new HealthMonitor(vpn::status, () -> networkOnline);
        return new GatewayService(vpn, new FakeNetwork(networkOnline), health, registry, null,
                () -> cfg, null, () -> elevated);
    }

    static void await(String what, BooleanSupplier cond) {
        long deadline = System.currentTimeMillis() + AWAIT_MS;
        while (System.currentTimeMillis() < deadline) {
            if (cond.getAsBoolean()) {
                return;
            }
            try {
                Thread.sleep(25);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        fail("timeout waiting for " + what);
    }

    @Test
    void unavailableVpnReachesBinariesMissingWithoutNpe() {
        AppConfig cfg = serverConfig(3, 200);
        FakeGatewayVpn vpn = new FakeGatewayVpn(false, null, null);
        GatewayService gateway = gateway(vpn, cfg, true, true);

        gateway.start();
        await("BINARIES_MISSING", () -> gateway.state() == GatewayState.BINARIES_MISSING);
        assertEquals(GatewayState.BINARIES_MISSING, gateway.state());
        // startGateway must never even be attempted without a working engine
        assertEquals(0, vpn.startGatewayCalls.get());
        gateway.close();
    }

    @Test
    void duplicateRebootstrapIsCoalescedToASingleRun() {
        AppConfig cfg = serverConfig(3, 200);
        FakeGatewayVpn vpn = new FakeGatewayVpn(false, null, null);
        GatewayService gateway = gateway(vpn, cfg, true, true);
        AtomicInteger binariesMissingArrivals = new AtomicInteger();
        gateway.addListener(new GatewayService.Listener() {
            @Override
            public void onGatewayStateChanged(GatewayState from, GatewayState to) {
                if (to == GatewayState.BINARIES_MISSING) {
                    binariesMissingArrivals.incrementAndGet();
                }
            }

            @Override
            public void onProgress(String step) {
            }
        });

        gateway.start();
        await("first bootstrap", () -> binariesMissingArrivals.get() >= 1);

        // two back-to-back requests while one rebootstrap is queued/running
        gateway.rebootstrap();
        gateway.rebootstrap();
        await("rebootstrap run", () -> binariesMissingArrivals.get() >= 2);
        settle();
        assertEquals(2, binariesMissingArrivals.get(),
                "duplicate rebootstrap must be coalesced into exactly one run");
        assertEquals(GatewayState.BINARIES_MISSING, gateway.state());
        gateway.close();
    }

    @Test
    void exhaustedRecoveryEndsInStableErrorAndExplicitRetryStillWorks() {
        AppConfig cfg = serverConfig(1, 50);
        FakeGatewayVpn vpn = new FakeGatewayVpn(true, null,
                new VpnException(VpnException.Kind.CONFIGURATION_ERROR, "tunnel rejected"));
        GatewayService gateway = gateway(vpn, cfg, true, true);

        gateway.start();
        await("terminal ERROR", () -> gateway.state() == GatewayState.ERROR);
        // exactly two attempts: the first plus the single scheduled retry
        assertEquals(2, vpn.startGatewayCalls.get());
        settle();
        assertEquals(GatewayState.ERROR, gateway.state(), "ERROR must be stable after exhaustion");

        // an operator retry is still allowed and clearly knocks the gateway back
        gateway.requestRecovery();
        await("retry proceeds", () -> vpn.startGatewayCalls.get() >= 4);
        await("ERROR again", () -> gateway.state() == GatewayState.ERROR);
        assertEquals(4, vpn.startGatewayCalls.get());
        gateway.close();
    }

    @Test
    void closeStopsLifecycleAndPreventsFurtherActivity() {
        AppConfig cfg = serverConfig(3, 200);
        FakeGatewayVpn vpn = new FakeGatewayVpn(false, null, null);
        GatewayService gateway = gateway(vpn, cfg, true, true);

        gateway.start();
        await("first bootstrap", () -> gateway.state() == GatewayState.BINARIES_MISSING);
        List<String> transitions = new CopyOnWriteArrayList<>();
        gateway.addListener(new GatewayService.Listener() {
            @Override
            public void onGatewayStateChanged(GatewayState from, GatewayState to) {
                transitions.add(from + "->" + to);
            }

            @Override
            public void onProgress(String step) {
            }
        });

        gateway.close();
        await("STOPPED", () -> gateway.state() == GatewayState.STOPPED);
        assertTrue(transitions.contains("BINARIES_MISSING->STOPPING"));
        assertTrue(transitions.contains("STOPPING->STOPPED"));

        int callsBefore = vpn.startGatewayCalls.get();
        gateway.rebootstrap();
        gateway.requestRecovery();
        try {
            Thread.sleep(300);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        assertEquals(callsBefore, vpn.startGatewayCalls.get());
        assertEquals(GatewayState.STOPPED, gateway.state());
    }

    private static void settle() {
        try {
            Thread.sleep(600);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}