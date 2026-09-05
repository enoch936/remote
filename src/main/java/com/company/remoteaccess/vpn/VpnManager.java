package com.company.remoteaccess.vpn;

import com.company.remoteaccess.core.authentication.ClientIdentity;
import com.company.remoteaccess.core.configuration.AppConfig;
import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.networking.FirewallManager;
import com.company.remoteaccess.networking.FirewallRule;
import com.company.remoteaccess.networking.IpHelpers;
import com.company.remoteaccess.networking.IpHelpers.Cidr;
import com.company.remoteaccess.networking.NatManager;
import com.company.remoteaccess.networking.NetworkException;
import com.company.remoteaccess.networking.RoutePlan;
import com.company.remoteaccess.networking.RoutingManager;
import com.company.remoteaccess.security.CredentialStore;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Orchestrates the VPN lifecycle around the WireGuard adapter: key handling,
 * configuration generation, tunnel start/stop, route/firewall/NAT wiring and
 * health checks.
 */
public final class VpnManager {

    private final VpnAdapter adapter;
    private final Supplier<AppConfig> config;
    private final CredentialStore credentials;
    private final RoutingManager routing;
    private final FirewallManager firewall;
    private final NatManager nat;
    private final KeyManager keyManager;

    public VpnManager(VpnAdapter adapter,
                      Supplier<AppConfig> config,
                      CredentialStore credentials,
                      RoutingManager routing,
                      FirewallManager firewall,
                      NatManager nat,
                      KeyManager keyManager) {
        this.adapter = adapter;
        this.config = config;
        this.credentials = credentials;
        this.routing = routing;
        this.firewall = firewall;
        this.nat = nat;
        this.keyManager = keyManager;
    }

    public VpnAdapter adapter() {
        return adapter;
    }

    public KeyManager keyManager() {
        return keyManager;
    }

    // ------------------------------------------------------------------
    // keys
    // ------------------------------------------------------------------

    public KeyManager.KeyPair ensureServerKeys() throws VpnException {
        return ensureKeys("server");
    }

    public KeyManager.KeyPair ensureClientKeys() throws VpnException {
        return ensureKeys("device-" + safeDeviceName());
    }

    public KeyManager.KeyPair ensureKeys(String name) throws VpnException {
        try {
            Optional<String> stored = credentials.get(name);
            if (stored.isPresent()) {
                String priv = stored.get();
                String pub = keyManager.derivePublicKey(priv);
                return new KeyManager.KeyPair(priv, pub);
            }
            KeyManager.KeyPair pair = keyManager.generateKeyPair();
            credentials.put(name, pair.privateKey());
            AppLogger.getLogger().info(LogCategory.AUTH,
                    "key pair generated for %s (private key stored securely)", name);
            return pair;
        } catch (IOException e) {
            throw new VpnException(VpnException.Kind.INTERNAL,
                    "unable to read/write credential store: " + e.getMessage(), e);
        }
    }

    public void revokeKeys(String name) {
        try {
            credentials.delete(name);
        } catch (IOException e) {
            AppLogger.getLogger().warn(LogCategory.AUTH, "key revocation failed for %s", name);
        }
    }

    private String safeDeviceName() {
        String n = config.get().clientDeviceName();
        return n == null || n.isBlank() ? "home" : n.replaceAll("[^A-Za-z0-9_-]", "_");
    }

    private String safeDevicePub() throws VpnException {
        return ensureClientKeys().publicKey();
    }

    // ------------------------------------------------------------------
    // GATEWAY (server) lifecycle
    // ------------------------------------------------------------------

    /** Full server bring-up. Returns the resulting status. */
    public VpnStatus startGateway(List<ClientIdentity> authorizedPeers) throws VpnException {
        AppConfig cfg = config.get();
        String tunnel = cfg.tunnelName();
        Cidr vpnSubnet = IpHelpers.parseCidr(cfg.vpnSubnet());
        String gatewayIp = IpHelpers.format(IpHelpers.nextHost(vpnSubnet.network()));
        String gatewayCidr = gatewayIp + "/" + vpnSubnet.prefix();

        KeyManager.KeyPair keys = ensureServerKeys();

        WgConfigBuilder builder = new WgConfigBuilder()
                .interfaceKeys(keys.privateKey(), gatewayCidr)
                .listenPort(cfg.listenPort())
                .mtu(cfg.mtu());
        for (ClientIdentity peer : authorizedPeers) {
            builder.addPeer(peer.publicKey(), peer.vpnAddress() + "/32", null,
                    cfg.persistentKeepalive());
        }
        String conf = builder.build();
        adapter.writeConfig(tunnel, conf);
        adapter.loadConfig(tunnel);
        adapter.start(tunnel);

        // Firewall: allow inbound UDP on the VPN listen port only.
        try {
            firewall.applyRule(FirewallRule.builder("wg-" + tunnel, "WireGuard listener")
                    .protocol(FirewallRule.Protocol.UDP)
                    .port(cfg.listenPort())
                    .direction(FirewallRule.Direction.IN)
                    .action(FirewallRule.Action.ALLOW)
                    .build());
        } catch (NetworkException e) {
            throw new VpnException(VpnException.Kind.PERMISSION_REQUIRED,
                    "Firewall rule not applied: " + e.getMessage());
        }

        // NAT is only required for full-tunnel internet sharing.
        if ("FULL_TUNNEL".equals(cfg.routingMode())) {
            applyGatewayNat(cfg, cfg.lanInterface(), cfg.lanCidr());
        }

        return adapter.status(tunnel);
    }

    /** Apply or refresh NAT for full-tunnel mode; report missing admin action. */
    public void applyGatewayNat(AppConfig cfg, String lanInterface, String lanCidr) throws VpnException {
        try {
            String vpnSubnetCidr = cfg.vpnSubnet();
            if (lanCidr == null || lanCidr.isBlank()) {
                throw new NetworkException(NetworkException.Kind.NOT_CONFIGURED,
                        "company LAN subnet is not configured; NAT cannot be set up");
            }
            List<String> actions = nat.missingRequirements(vpnSubnetCidr, lanInterface);
            if (!actions.isEmpty() && !nat.isEnabled()) {
                // do not silently fail: surface the required administrator action
                throw new VpnException(VpnException.Kind.PERMISSION_REQUIRED,
                        "Full-tunnel NAT requires configuration: " + String.join("; ", actions));
            }
            nat.enableNat(vpnSubnetCidr, lanInterface, lanCidr);
        } catch (NetworkException e) {
            AppLogger.getLogger().warn(LogCategory.FIREWALL, "NAT setup: %s", e.getMessage());
        }
    }

    // ------------------------------------------------------------------
    // CLIENT lifecycle
    // ------------------------------------------------------------------

    public VpnStatus startClient(String serverPublicKey, String clientVpnIp,
                                 List<String> allowedIps, String dns) throws VpnException {
        AppConfig cfg = config.get();
        String tunnel = cfg.tunnelName();
        KeyManager.KeyPair keys = ensureClientKeys();

        String serverEndpoint = cfg.clientServerEndpoint();
        if (serverEndpoint == null || serverEndpoint.isBlank()) {
            throw new VpnException(VpnException.Kind.CONFIGURATION_ERROR,
                    "gateway endpoint not configured; pair the device first");
        }
        String endpoint = serverEndpoint.contains(":")
                ? serverEndpoint
                : serverEndpoint + ":" + cfg.listenPort();

        WgConfigBuilder builder = new WgConfigBuilder()
                .interfaceKeys(keys.privateKey(), clientVpnIp)
                .mtu(cfg.mtu())
                .listenPort(0);
        if (dns != null && !dns.isBlank()) {
            builder.dns(dns);
        }
        builder.addPeer(serverPublicKey, String.join(",", allowedIps), endpoint,
                cfg.persistentKeepalive());
        String conf = builder.build();

        adapter.writeConfig(tunnel, conf);
        adapter.loadConfig(tunnel);
        adapter.start(tunnel);
        AppLogger.getLogger().info(LogCategory.VPN,
                "client tunnel started towards %s", endpoint);
        return adapter.status(tunnel);
    }

    public VpnStatus stopTunnel() {
        String tunnel = config.get().tunnelName();
        try {
            adapter.stop(tunnel);
        } catch (VpnException e) {
            AppLogger.getLogger().warn(LogCategory.VPN, "stop: %s", e.getMessage());
        }
        return VpnStatus.down(tunnel);
    }

    /** Add an authorized peer to the running interface without a restart. */
    public void addPeerToRunning(String publicKey, String vpnAddress) {
        try {
            adapter.ensureAvailable();
            adapter.setPeer(config.get().tunnelName(), publicKey, vpnAddress + "/32");
            AppLogger.getLogger().info(LogCategory.SERVER,
                    "peer %s/%s added to running interface", vpnAddress, publicKey);
        } catch (VpnException e) {
            if (e.kind() != VpnException.Kind.BINARIES_MISSING) {
                AppLogger.getLogger().warn(LogCategory.SERVER,
                        "live peer add skipped: %s", e.getMessage());
            }
        }
    }

    public void removeAllManagedNetworking() {
        try {
            routing.undoAllManaged();
        } catch (NetworkException e) {
            AppLogger.getLogger().warn(LogCategory.ROUTING, "cleanup: %s", e.getMessage());
        }
    }

    public VpnStatus status() {
        return adapter.status(config.get().tunnelName());
    }

    public RoutingManager routing() {
        return routing;
    }
}