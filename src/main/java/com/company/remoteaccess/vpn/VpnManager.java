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
import com.company.remoteaccess.security.Validation;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Orchestrates the VPN lifecycle around the WireGuard adapter: key handling,
 * configuration generation, tunnel start/stop, route/firewall/NAT wiring and
 * health checks.
 */
public final class VpnManager implements GatewayVpn {

    private final VpnAdapter adapter;
    private final Supplier<AppConfig> config;
    private final CredentialStore credentials;
    private final RoutingManager routing;
    private final FirewallManager firewall;
    private final NatManager nat;
    private final KeyManager keyManager;
    private final boolean available;

    private volatile boolean natManaged;

    public VpnManager(VpnAdapter adapter,
                      Supplier<AppConfig> config,
                      CredentialStore credentials,
                      RoutingManager routing,
                      FirewallManager firewall,
                      NatManager nat,
                      KeyManager keyManager) {
        this(adapter, config, credentials, routing, firewall, nat, keyManager, true);
    }

    public VpnManager(VpnAdapter adapter,
                      Supplier<AppConfig> config,
                      CredentialStore credentials,
                      RoutingManager routing,
                      FirewallManager firewall,
                      NatManager nat,
                      KeyManager keyManager,
                      boolean available) {
        this.adapter = adapter;
        this.config = config;
        this.credentials = credentials;
        this.routing = routing;
        this.firewall = firewall;
        this.nat = nat;
        this.keyManager = keyManager;
        this.available = available;
    }

    public VpnAdapter adapter() {
        return adapter;
    }

    public KeyManager keyManager() {
        return keyManager;
    }

    /** Explicit engine state: the WireGuard tooling is present and verified. */
    public boolean isAvailable() {
        return available;
    }

    private void requireAvailable() throws VpnException {
        if (!available) {
            throw new VpnException(VpnException.Kind.BINARIES_MISSING,
                    "WireGuard (wg) is not installed or not on PATH.");
        }
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
        requireAvailable();
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
        ensureTunnelConfigured(tunnel, conf);
        ensureTunnelRunning(tunnel);

        // Firewall: allow inbound UDP on the VPN listen port only.
        try {
            firewall.applyRule(FirewallRule.builder("wg-" + tunnel, "WireGuard listener")
                    .protocol(FirewallRule.Protocol.UDP)
                    .port(cfg.listenPort())
                    .direction(FirewallRule.Direction.IN)
                    .action(FirewallRule.Action.ALLOW)
                    .build());
        } catch (NetworkException e) {
            throw new VpnException(VpnException.Kind.FIREWALL_CONFIGURATION,
                    "Firewall rule not applied: " + e.getMessage());
        }

        // NAT is only required for full-tunnel internet sharing.
        if ("FULL_TUNNEL".equals(cfg.routingMode())) {
            applyGatewayNat(cfg, cfg.lanInterface(), cfg.lanCidr());
        }

        return adapter.status(tunnel);
    }

    /**
     * Idempotent tunnel configuration: stage the config and install the tunnel
     * only when it does not already exist. Repeated calls never reinstall.
     */
    public void ensureTunnelConfigured(String tunnelName, String conf) throws VpnException {
        adapter.writeConfig(tunnelName, conf);
        adapter.ensureInstalled(tunnelName);
    }

    /**
     * Idempotent tunnel bring-up: reuse an already-running tunnel, otherwise
     * install when missing and start it. Safe to call repeatedly.
     */
    public void ensureTunnelRunning(String tunnelName) throws VpnException {
        if (adapter.isRunning(tunnelName)) {
            AppLogger.getLogger().info(LogCategory.VPN,
                    "tunnel %s already running; verifying state", tunnelName);
            adapter.verifyConfig(tunnelName);
            return;
        }
        if (!adapter.isInstalled(tunnelName)) {
            AppLogger.getLogger().info(LogCategory.VPN,
                    "tunnel %s not installed; installing", tunnelName);
            adapter.ensureInstalled(tunnelName);
        }
        adapter.start(tunnelName);
    }

    /** Configure - then verify - NAT for full-tunnel mode. */
    public void applyGatewayNat(AppConfig cfg, String lanInterface, String lanCidr) throws VpnException {
        String vpnSubnetCidr = cfg.vpnSubnet();
        if (lanCidr == null || lanCidr.isBlank()) {
            throw new VpnException(VpnException.Kind.NAT_CONFIGURATION,
                    "company LAN subnet is not configured; NAT cannot be set up. "
                            + "Set the LAN subnet in server setup or switch to split tunneling.");
        }
        // Configure first. The old code checked missingRequirements and bailed
        // before applying anything, so full-tunnel servers could never configure
        // their own NAT on first boot.
        try {
            nat.enableNat(vpnSubnetCidr, lanInterface, lanCidr);
            natManaged = true;
        } catch (NetworkException e) {
            throw new VpnException(VpnException.Kind.NAT_CONFIGURATION,
                    "Full-tunnel NAT could not be enabled: " + e.getMessage(), e);
        }
        // Then verify: if the rules this app is responsible for are absent, we
        // did not go ONLINE - the state is reported as a real failure.
        NatManager.NatResult verified = nat.verifyNat(vpnSubnetCidr, lanInterface);
        if (verified.state() == NatManager.State.NOT_ENABLED
                || verified.state() == NatManager.State.ERROR) {
            throw new VpnException(VpnException.Kind.NAT_CONFIGURATION, verified.summary());
        }
        if (verified.state() == NatManager.State.PARTIAL) {
            AppLogger.getLogger().warn(LogCategory.FIREWALL,
                    "NAT partially verified: %s", verified.summary());
            return;
        }
        AppLogger.getLogger().info(LogCategory.FIREWALL, "NAT verified: %s", verified.summary());
    }

    /** Remove the NAT state this gateway applied (reverse of applyGatewayNat). */
    public void removeAllManagedNat() {
        if (!natManaged || nat == null) {
            return;
        }
        AppConfig cfg = config.get();
        try {
            nat.disableNat(cfg.vpnSubnet(), cfg.lanInterface(), cfg.lanCidr());
        } catch (NetworkException e) {
            AppLogger.getLogger().warn(LogCategory.FIREWALL,
                    "NAT cleanup skipped (may require elevation on next start): %s", e.getMessage());
        }
        natManaged = false;
    }

    // ------------------------------------------------------------------
    // CLIENT lifecycle
    // ------------------------------------------------------------------

    public VpnStatus startClient(String serverPublicKey, String clientVpnIp,
                                 List<String> allowedIps, String dns) throws VpnException {
        requireAvailable();
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
        try {
            Validation.requireWireGuardKey(serverPublicKey, "server public key");
            Validation.requireEndpoint(endpoint, "gateway endpoint");
        } catch (IllegalArgumentException e) {
            throw new VpnException(VpnException.Kind.CONFIGURATION_ERROR,
                    "invalid gateway configuration: " + e.getMessage());
        }

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

        ensureTunnelConfigured(tunnel, conf);
        ensureTunnelRunning(tunnel);
        AppLogger.getLogger().info(LogCategory.VPN,
                "client tunnel started towards %s", endpoint);
        return adapter.status(tunnel);
    }

    public VpnStatus stopTunnel() {
        String tunnel = config.get().tunnelName();
        if (!available) {
            return VpnStatus.down(tunnel);
        }
        try {
            adapter.stop(tunnel);
        } catch (VpnException e) {
            AppLogger.getLogger().warn(LogCategory.VPN, "stop: %s", e.getMessage());
        }
        return VpnStatus.down(tunnel);
    }

    /** Add an authorized peer to the running interface without a restart. */
    public void addPeerToRunning(String publicKey, String vpnAddress) {
        if (!available || !adapter.isRunning(config.get().tunnelName())) {
            AppLogger.getLogger().debug(LogCategory.SERVER,
                    "live peer add skipped: tunnel not running or VPN unavailable");
            return;
        }
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

    /** Remove every firewall rule this application created (reverse of applyRule). */
    public void removeAllManagedFirewall() {
        try {
            firewall.removeAllManaged();
        } catch (Exception e) {
            AppLogger.getLogger().warn(LogCategory.FIREWALL, "firewall cleanup: %s", e.getMessage());
        }
    }

    public VpnStatus status() {
        if (!available) {
            return VpnStatus.down(config.get().tunnelName());
        }
        return adapter.status(config.get().tunnelName());
    }

    public RoutingManager routing() {
        return routing;
    }
}