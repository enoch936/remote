package com.company.remoteaccess.client;

import com.company.remoteaccess.core.configuration.AppConfig;
import com.company.remoteaccess.core.configuration.ConfigManager;
import com.company.remoteaccess.core.state.ConnectionState;
import com.company.remoteaccess.networking.NetInterface;
import com.company.remoteaccess.networking.NetworkException;
import com.company.remoteaccess.networking.NetworkManager;
import com.company.remoteaccess.networking.NetworkManager.NetworkSnapshot;
import com.company.remoteaccess.networking.RouteEntry;
import com.company.remoteaccess.networking.RoutePlan;
import com.company.remoteaccess.networking.RouteManifest;
import com.company.remoteaccess.networking.RoutingManager;
import com.company.remoteaccess.platform.CommandResult;
import com.company.remoteaccess.platform.CommandRunner;
import com.company.remoteaccess.security.CredentialStore;
import com.company.remoteaccess.security.PairingToken;
import com.company.remoteaccess.vpn.KeyManager;
import com.company.remoteaccess.vpn.VpnAdapter;
import com.company.remoteaccess.vpn.VpnException;
import com.company.remoteaccess.vpn.VpnManager;
import com.company.remoteaccess.vpn.VpnPeer;
import com.company.remoteaccess.vpn.VpnStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientServiceTest {

    private static final String PUB = "S".repeat(43) + "=";

    @TempDir
    Path tmp;

    private ConfigManager configManager;
    private CredentialStore credentials;
    private ClientService service;
    private VpnManager vpn;
    private FakeVpnAdapter adapter;
    private FakeRouting routing;

    @BeforeEach
    void setUp() throws Exception {
        configManager = new ConfigManager(tmp.resolve("config.yaml"));
        configManager.save(AppConfig.create()
                .with("routing.mode", "SPLIT_TUNNEL")
                .with("client.serverEndpoint", "gw.example.com:51820"));
        credentials = new CredentialStore(tmp.resolve("secrets"));
        credentials.initialize();

        adapter = new FakeVpnAdapter();
        FakeRunner runner = new FakeRunner();
        routing = new FakeRouting(tmp.resolve("routes.json"));
        vpn = new VpnManager(adapter,
                configManager::load,
                credentials,
                routing,
                null,
                null,
                new KeyManager(runner, "wg"));
        FakeNetwork network = new FakeNetwork();
        FakeTester tester = new FakeTester();
        service = new ClientService(configManager::load, configManager, credentials,
                vpn, network, routing, tester);
    }

    @Test
    void unpairedDeviceFailsWithAuthError() throws Exception {
        service.connect();
        await(ConnectionState.AUTH_FAILED);
        assertTrue(service.lastFailureMessage().contains("not paired"),
                () -> "unexpected: " + service.lastFailureMessage());
    }

    @Test
    void pairingThenConnectReachesConnected() throws Exception {
        PairingToken token = new PairingToken("HQ", "gw.example.com", 51820,
                PUB, "10.50.0.2", "ot-token-1");
        assertTrue(service.completePairing(token, "dev-laptop"));
        assertTrue(service.isRegistered());

        service.connect();
        await(ConnectionState.CONNECTED);
        assertTrue(adapter.lastConfig.contains("[Peer]"));
        assertTrue(adapter.lastConfig.contains("AllowedIPs = 10.50.0.0/24"));
        assertTrue(service.status().running());
    }

    @Test
    void connectWithFailedVerificationFails() throws Exception {
        pairing();
        service = withFailingTester();
        service.connect();
        await(ConnectionState.VPN_FAILED);
        assertTrue(service.lastFailureMessage().contains("verification"));
    }

    @Test
    void disconnectFromConnectedReturnsOffline() throws Exception {
        pairing();
        service.connect();
        await(ConnectionState.CONNECTED);
        service.disconnect();
        waitUntil(() -> service.state() == ConnectionState.OFFLINE);
        assertFalse(service.status().running());
        assertEquals(Duration.ZERO, service.sessionDuration());
    }

    @Test
    void disconnectWhenOfflineIsNoOp() {
        service.disconnect();
        assertEquals(ConnectionState.OFFLINE, service.state());
    }

    @Test
    void forgetPairingClearsRegistration() throws Exception {
        pairing();
        assertTrue(service.isRegistered());
        service.forgetPairing();
        assertFalse(service.isRegistered());
    }

    private void pairing() throws Exception {
        PairingToken token = new PairingToken("HQ", "gw.example.com", 51820,
                PUB, "10.50.0.2", "ot-token-1");
        service.completePairing(token, "dev-laptop");
    }

    @Test
    void pairingRecordsDeviceKeyPin() throws Exception {
        pairing();
        assertEquals(ClientService.keyFingerprint(PUB),
                configManager.load().clientPubKeyHash());
    }

    @Test
    void changedDeviceKeyBlocksConnect() throws Exception {
        pairing();
        configManager.save(AppConfig.create()
                .with("mode", "CLIENT")
                .with("client.serverEndpoint", "gw.example.com:51820")
                .with("client.vpnIp", "10.50.0.2")
                .with("client.pairApplied", true)
                .with("client.deviceName", "dev-laptop")
                .with("client.pubKeyHash",
                        ClientService.keyFingerprint("Q".repeat(43) + "=")));
        service.connect();
        await(ConnectionState.AUTH_FAILED);
        assertTrue(service.lastFailureMessage().contains("changed since pairing"),
                () -> "unexpected: " + service.lastFailureMessage());
    }

    @Test
    void legacyPairingWithoutPinConnects() throws Exception {
        credentials.put(ClientService.SERVER_PUB_KEY_CRED, PUB);
        configManager.save(AppConfig.create()
                .with("mode", "CLIENT")
                .with("client.serverEndpoint", "gw.example.com:51820")
                .with("client.vpnIp", "10.50.0.2")
                .with("client.pairApplied", true));
        service.connect();
        await(ConnectionState.CONNECTED);
        assertTrue(service.status().running());
    }

    private ClientService withFailingTester() {
        NetworkManager network = new FakeNetwork();
        ClientService svc = new ClientService(configManager::load, configManager, credentials,
                vpn, network, routing, new FakeTester(true));
        return svc;
    }

    private void await(ConnectionState settled) {
        long deadline = System.currentTimeMillis() + 10_000;
        while (System.currentTimeMillis() < deadline) {
            if (service.state() == settled) {
                return;
            }
            try {
                Thread.sleep(25);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        throw new AssertionError("expected " + settled + " but state=" + service.state()
                + " lastFailure=" + service.lastFailureMessage());
    }

    private static void waitUntil(java.util.function.BooleanSupplier cond) {
        long deadline = System.currentTimeMillis() + 10_000;
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
        throw new AssertionError("condition not met within 10s");
    }

    // ------------------------------------------------------------------
    // doubles
    // ------------------------------------------------------------------

    static class FakeVpnAdapter implements VpnAdapter {
        String lastConfig;
        boolean running;

        @Override
        public void ensureAvailable() {
        }

        @Override
        public void writeConfig(String tunnelName, String configText) {
            this.lastConfig = configText;
        }

        @Override
        public void loadConfig(String tunnelName) {
        }

        @Override
        public void start(String tunnelName) {
            this.running = true;
        }

        @Override
        public void stop(String tunnelName) {
            this.running = false;
        }

        @Override
        public void removeConfig(String tunnelName) {
            this.running = false;
        }

        @Override
        public VpnStatus status(String tunnelName) {
            if (!running) {
                return VpnStatus.down(tunnelName);
            }
            return new VpnStatus(tunnelName, true, PUB, 51820, null,
                    List.of(new VpnPeer(PUB, "1.2.3.4:51820", List.of("10.50.0.0/24"), 5, 100, 100)));
        }
    }

    static class FakeRunner extends CommandRunner {
        @Override
        public CommandResult run(String... command) {
            return new CommandResult(0, "W".repeat(43) + "=", "");
        }

        @Override
        public CommandResult run(List<String> command, long timeoutSeconds) {
            return run(command.toArray(new String[0]));
        }

        @Override
        public CommandResult runWithInput(List<String> command, String stdinData, long timeoutSeconds) {
            return new CommandResult(0, PUB, "");
        }
    }

    static class FakeRouting extends RoutingManager {
        FakeRouting(Path manifest) {
            super(null, manifest);
        }

        @Override
        public List<RouteEntry> currentRoutes() {
            return List.of();
        }

        @Override
        public void applyPlan(RoutePlan plan) {
        }

        @Override
        public void undoPlan(RoutePlan plan) {
        }

        @Override
        protected void doAddRoute(RouteEntry entry) {
        }

        @Override
        protected void doRemoveRoute(RouteEntry entry) {
        }
    }

    static class FakeNetwork extends NetworkManager {
        FakeNetwork() {
            super(null, Duration.ofMinutes(1));
        }

        @Override
        public NetworkSnapshot snapshot() {
            return new NetworkSnapshot(List.of(new NetInterface(1, "Ethernet",
                    NetInterface.Type.ETHERNET, true, "aa", List.of("192.168.1.20/24"), 1000)),
                    true);
        }
    }

    static class FakeTester extends TunnelTester {
        private final boolean fail;

        FakeTester() {
            this(false);
        }

        FakeTester(boolean fail) {
            super(null, null);
            this.fail = fail;
        }

        @Override
        public ConnectionReport run(VpnStatus vpn, String gatewayVpnIp,
                                    String companyCidr, boolean fullTunnel, String probeHost) {
            String name = fail ? "probe" : "handshake";
            boolean ok = !fail;
            return new ConnectionReport(List.of(
                    new ConnectionReport.Check(name, ok, ok ? "ok" : "verification failed", 1)));
        }
    }
}