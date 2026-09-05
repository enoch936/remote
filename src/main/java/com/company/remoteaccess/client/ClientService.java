package com.company.remoteaccess.client;

import com.company.remoteaccess.core.authentication.ClientIdentity;
import com.company.remoteaccess.core.configuration.AppConfig;
import com.company.remoteaccess.core.configuration.ConfigManager;
import com.company.remoteaccess.core.state.ConnectionState;
import com.company.remoteaccess.core.state.StateMachine;
import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.networking.IpHelpers;
import com.company.remoteaccess.networking.NetworkManager;
import com.company.remoteaccess.networking.NetworkManager.NetworkSnapshot;
import com.company.remoteaccess.networking.NetworkException;
import com.company.remoteaccess.networking.RoutePlan;
import com.company.remoteaccess.networking.RoutingManager;
import com.company.remoteaccess.security.CredentialStore;
import com.company.remoteaccess.security.PairingToken;
import com.company.remoteaccess.vpn.VpnException;
import com.company.remoteaccess.vpn.VpnManager;
import com.company.remoteaccess.vpn.VpnStatus;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * The home/client controller. Owns the connect/disconnect orchestration around
 * the state machine and never leaves the UI in an ambiguous state.
 */
public final class ClientService {

    public static final String SERVER_PUB_KEY_CRED = "server-public-key";

    public final StateMachine state = new StateMachine();

    private final Supplier<AppConfig> config;
    private final ConfigManager configManager;
    private final CredentialStore credentials;
    private final VpnManager vpn;
    private final NetworkManager network;
    private final RoutingManager routing;
    private final TunnelTester tester;
    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "client-service");
        t.setDaemon(true);
        return t;
    });

    private volatile Instant connectedAt;
    private volatile Instant disconnectedAt;
    private final AtomicReference<ConnectionReport> lastReport = new AtomicReference<>();
    private final AtomicReference<String> lastFailure = new AtomicReference<>();
    private RoutePlan lastPlan;

    public ClientService(Supplier<AppConfig> config,
                         ConfigManager configManager,
                         CredentialStore credentials,
                         VpnManager vpn,
                         NetworkManager network,
                         RoutingManager routing,
                         TunnelTester tester) {
        this.config = config;
        this.configManager = configManager;
        this.credentials = credentials;
        this.vpn = vpn;
        this.network = network;
        this.routing = routing;
        this.tester = tester;
    }

    private CredentialStore credentials() {
        return credentials;
    }

    // ------------------------------------------------------------------
    // pairing
    // ------------------------------------------------------------------

    public boolean isRegistered() throws IOException {
        return credentials.has(SERVER_PUB_KEY_CRED)
                && config.get().clientVpnIp() != null && !config.get().clientVpnIp().isBlank()
                && config.get().clientServerEndpoint() != null
                && !config.get().clientServerEndpoint().isBlank();
    }

    /**
     * Complete pairing with the data received from the gateway (QR or manual).
     * Stores the pinned server public key and the server-assigned client address.
     */
    public synchronized boolean completePairing(PairingToken token, String deviceName) throws Exception {
        if (token == null || token.oneTimeToken() == null || token.oneTimeToken().isBlank()) {
            throw new IllegalArgumentException("pairing payload is missing the verification token");
        }
        requireVpn().ensureClientKeys(); // generate/store our keys first
        credentials.put(SERVER_PUB_KEY_CRED, token.serverPublicKey());
        String endpoint = token.serverHost() + ":" + token.listenPort();
        AppConfig cfg = config.get();
        cfg = cfg.with("client.deviceName", deviceName)
                .with("client.serverEndpoint", endpoint)
                .with("client.vpnIp", token.assignedClientAddress())
                .with("server.name", token.serverName())
                .with("client.pairApplied", true);
        configManager.save(cfg);
        AppLogger.getLogger().info(LogCategory.AUTH,
                "device paired: server='%s' endpoint=%s clientIp=%s",
                token.serverName(), endpoint, token.assignedClientAddress());
        return true;
    }

    public void forgetPairing() throws IOException {
        String device = "device-" + safeDeviceName(config.get());
        credentials.delete(SERVER_PUB_KEY_CRED);
        AppConfig cfg = config.get();
        cfg = cfg.with("client.serverEndpoint", "")
                .with("client.vpnIp", "")
                .with("client.pairApplied", false);
        try {
            configManager.save(cfg);
        } catch (IOException ignored) {
            // best effort
        }
        if (vpn != null) {
            vpn.revokeKeys(device);
        }
    }

    // ------------------------------------------------------------------
    // connect / disconnect
    // ------------------------------------------------------------------

    public void connect() {
        executor.submit(this::connectInternal);
    }

    private VpnManager requireVpn() throws VpnException {
        if (vpn == null) {
            throw new VpnException(VpnException.Kind.BINARIES_MISSING,
                    "WireGuard is not installed or not on PATH. Install it from wireguard.com.");
        }
        return vpn;
    }

    private void connectInternal() {
        ConnectionState current = state.get();
        if (current == ConnectionState.CONNECTED || current.isTransient()) {
            return;
        }
        lastFailure.set(null);
        transition(ConnectionState.INITIALIZING);
        try {
            VpnManager vpn = requireVpn();
            AppConfig cfg = config.get();
            Optional<String> serverPub = credentials.get(SERVER_PUB_KEY_CRED);
            if (serverPub.isEmpty()) {
                fail(ConnectionState.AUTH_FAILED, "This device is not paired with a gateway.");
                return;
            }
            String myIp = cfg.clientVpnIp();
            if (myIp == null || myIp.isBlank()) {
                fail(ConnectionState.AUTH_FAILED,
                        "Pairing is incomplete (no VPN address assigned).");
                return;
            }
            String endpoint = cfg.clientServerEndpoint();
            if (endpoint == null || endpoint.isBlank()) {
                fail(ConnectionState.AUTH_FAILED, "Gateway endpoint is not configured.");
                return;
            }

            transition(ConnectionState.CHECKING_NETWORK);
            NetworkSnapshot snap = network.snapshot();
            if (!snap.online()) {
                fail(ConnectionState.NETWORK_UNAVAILABLE,
                        "No active internet connection was detected.");
                return;
            }

            transition(ConnectionState.AUTHENTICATING);
            vpn.ensureClientKeys(); // establish our unique identity

            transition(ConnectionState.CONNECTING);
            IpHelpers.Cidr vpnSubnet = IpHelpers.parseCidr(cfg.vpnSubnet());
            String gatewayIp = IpHelpers.format(IpHelpers.nextHost(vpnSubnet.network()));
            boolean fullTunnel = "FULL_TUNNEL".equals(cfg.routingMode());
            List<String> allowedIps = new ArrayList<>();
            if (fullTunnel) {
                allowedIps.add("0.0.0.0/0");
            } else {
                allowedIps.add(cfg.vpnSubnet());
                if (cfg.lanCidr() != null && !cfg.lanCidr().isBlank()) {
                    allowedIps.add(cfg.lanCidr());
                } else {
                    AppLogger.getLogger().warn(LogCategory.CLIENT,
                            "no company subnet configured for split-tunnel routing");
                }
                for (String extra : cfg.extraRoutes()) {
                    allowedIps.add(extra);
                }
            }
            AppLogger.getLogger().info(LogCategory.CLIENT,
                    "tunnel allowed IPs: %s", String.join(", ", allowedIps));
            VpnStatus status = vpn.startClient(serverPub.get(), myIp + "/32",
                    allowedIps, cfg.clientDnsOverride());

            transition(ConnectionState.CONFIGURING);
            lastPlan = buildRoutePlan(cfg, gatewayIp, fullTunnel, endpoint);
            if (routing != null) {
                routing.applyPlan(lastPlan);
            } else {
                AppLogger.getLogger().warn(LogCategory.ROUTING,
                        "routing manager unavailable; routes not applied");
            }

            transition(ConnectionState.VERIFYING);
            String probe = cfg.lanCidr() == null || cfg.lanCidr().isBlank()
                    ? gatewayIp : IpHelpers.lowestHost(IpHelpers.parseCidr(cfg.lanCidr()));
            ConnectionReport report = tester.run(vpn.status(), gatewayIp,
                    cfg.lanCidr(), fullTunnel, probe);
            lastReport.set(report);
            if (report.anyFailed()) {
                fail(ConnectionState.VPN_FAILED,
                        "Tunnel verification failed: " + failedNames(report));
                return;
            }

            connectedAt = Instant.now();
            disconnectedAt = null;
            transition(ConnectionState.CONNECTED);
            AppLogger.getLogger().info(LogCategory.CLIENT,
                    "connected to %s (ip %s)", cfg.serverName(), myIp);
        } catch (VpnException e) {
            fail(mapVpnFailure(e), e.getMessage());
        } catch (NetworkException e) {
            fail(e.kind() == NetworkException.Kind.PERMISSION_REQUIRED
                    ? ConnectionState.PERMISSION_REQUIRED : ConnectionState.VPN_FAILED,
                    e.getMessage());
        } catch (IOException e) {
            fail(ConnectionState.ERROR, "Credential store error: " + e.getMessage());
        } catch (Exception e) {
            AppLogger.getLogger().error(LogCategory.CLIENT, e, "connect failed");
            fail(ConnectionState.ERROR, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private RoutePlan buildRoutePlan(AppConfig cfg, String gatewayIp, boolean fullTunnel,
                                     String endpoint) {
        RoutePlan plan = new RoutePlan()
                .mode(fullTunnel ? RoutePlan.Mode.FULL_TUNNEL : RoutePlan.Mode.SPLIT_TUNNEL)
                .tunnelInterface(cfg.tunnelName(), gatewayIp);
        if (cfg.lanCidr() != null && !cfg.lanCidr().isBlank()) {
            plan.companySubnet(IpHelpers.parseCidr(cfg.lanCidr()));
        }
        plan.companySubnet(IpHelpers.parseCidr(cfg.vpnSubnet()));
        for (String extra : cfg.extraRoutes()) {
            plan.extraSubnet(IpHelpers.parseCidr(extra));
        }
        if (fullTunnel) {
            plan.serverPublicEndpoint(endpoint);
        }
        return plan;
    }

    public void disconnect() {
        executor.submit(this::disconnectInternal);
    }

    private void disconnectInternal() {
        if (state.get() == ConnectionState.OFFLINE) {
            return;
        }
        transition(ConnectionState.INITIALIZING);
        try {
            if (vpn != null) {
                vpn.stopTunnel();
            }
            if (routing != null) {
                if (lastPlan != null) {
                    routing.undoPlan(lastPlan);
                    lastPlan = null;
                }
                routing.undoAllManaged();
            }
            NetworkSnapshot snap = network.snapshot();
            if (!snap.online()) {
                AppLogger.getLogger().warn(LogCategory.CLIENT,
                        "disconnect complete but the local network is not reachable");
            }
        } catch (Exception e) {
            AppLogger.getLogger().error(LogCategory.CLIENT, e, "disconnect cleanup failed");
        } finally {
            connectedAt = null;
            disconnectedAt = Instant.now();
            transition(ConnectionState.OFFLINE);
        }
    }

    // ------------------------------------------------------------------
    // queries for the dashboard
    // ------------------------------------------------------------------

    public ConnectionState state() {
        return state.get();
    }

    public ConnectionReport lastReport() {
        return lastReport.get();
    }

    public String lastFailureMessage() {
        return lastFailure.get();
    }

    public Duration sessionDuration() {
        if (connectedAt == null) {
            return Duration.ZERO;
        }
        return Duration.between(connectedAt, Instant.now());
    }

    public VpnStatus status() {
        return vpn == null ? VpnStatus.down(config.get().tunnelName()) : vpn.status();
    }

    public String serverName() {
        return config.get().serverName();
    }

    public String vpnIp() {
        String ip = config.get().clientVpnIp();
        return ip == null ? "" : ip;
    }

    private static String safeDeviceName(AppConfig cfg) {
        String n = cfg.clientDeviceName();
        return n == null || n.isBlank() ? "home" : n.replaceAll("[^A-Za-z0-9_-]", "_");
    }

    // ------------------------------------------------------------------
    // state helpers
    // ------------------------------------------------------------------

    private void transition(ConnectionState next) {
        try {
            state.transitionTo(next);
        } catch (IllegalStateException e) {
            AppLogger.getLogger().debug(LogCategory.CLIENT,
                    "state transition rejected: %s", e.getMessage());
        }
    }

    private void fail(ConnectionState failureState, String message) {
        lastFailure.set(message);
        AppLogger.getLogger().warn(LogCategory.CLIENT, "connect failed (%s): %s",
                failureState, message);
        transition(failureState);
    }

    private static String failedNames(ConnectionReport report) {
        return report.checks().stream()
                .filter(c -> !c.ok())
                .map(ConnectionReport.Check::name)
                .reduce((a, b) -> a + ", " + b)
                .orElse("unknown checks");
    }

    private static ConnectionState mapVpnFailure(VpnException e) {
        return switch (e.kind()) {
            case BINARIES_MISSING -> ConnectionState.SERVER_UNAVAILABLE;
            case PERMISSION_REQUIRED -> ConnectionState.PERMISSION_REQUIRED;
            case START_FAILED, CONFIGURATION_ERROR -> ConnectionState.VPN_FAILED;
            default -> ConnectionState.ERROR;
        };
    }
}