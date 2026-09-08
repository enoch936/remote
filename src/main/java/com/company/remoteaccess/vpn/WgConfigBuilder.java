package com.company.remoteaccess.vpn;

import com.company.remoteaccess.networking.IpHelpers;
import com.company.remoteaccess.security.Validation;

import java.util.ArrayList;
import java.util.List;

/**
 * Builds standard wg-quick configuration text. The generated config is passed
 * directly to WireGuard; no cryptography is implemented in this application.
 */
public final class WgConfigBuilder {

    public record PeerSpec(String publicKey, String allowedIps, String endpoint,
                           Integer persistentKeepalive) {
    }

    private String privateKey;
    private String address;
    private String dns;
    private Integer mtu;
    private Integer listenPort;
    private final List<PeerSpec> peers = new ArrayList<>();

    public WgConfigBuilder interfaceKeys(String privateKey, String address) {
        this.privateKey = privateKey;
        this.address = address;
        return this;
    }

    public WgConfigBuilder dns(String dns) {
        this.dns = dns;
        return this;
    }

    public WgConfigBuilder mtu(int mtu) {
        this.mtu = mtu;
        return this;
    }

    public WgConfigBuilder listenPort(int port) {
        this.listenPort = port;
        return this;
    }

    public WgConfigBuilder addPeer(String publicKey, String allowedIps, String endpoint,
                                   Integer keepalive) {
        peers.add(new PeerSpec(publicKey, allowedIps, endpoint, keepalive));
        return this;
    }

    public WgConfigBuilder addPeer(PeerSpec spec) {
        peers.add(spec);
        return this;
    }

    public String build() {
        if (privateKey == null || privateKey.isBlank()) {
            throw new IllegalStateException("interface private key is required");
        }
        if (address == null || address.isBlank()) {
            throw new IllegalStateException("interface address is required");
        }
        // Strict validation before anything is written to the tunnel config:
        // malformed keys/endpoints/CIDRs would otherwise reach wg-quick verbatim.
        Validation.requireWireGuardKey(privateKey, "interface private key");
        try {
            IpHelpers.parseCidr(address);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("interface address is invalid: " + address);
        }
        Validation.requireDnsList(dns, "DNS");
        for (PeerSpec p : peers) {
            Validation.requireWireGuardKey(p.publicKey(), "peer public key");
            if (p.allowedIps() != null && !p.allowedIps().isBlank()) {
                for (String cidr : p.allowedIps().split(",")) {
                    String c = cidr.trim();
                    try {
                        IpHelpers.parseCidr(c);
                    } catch (IllegalArgumentException e) {
                        throw new IllegalArgumentException("peer AllowedIPs contains invalid CIDR: " + c);
                    }
                }
            }
            if (p.endpoint() != null && !p.endpoint().isBlank()) {
                Validation.requireEndpoint(p.endpoint(), "peer endpoint");
            }
        }
        // An empty peer list is valid: a gateway with no paired devices is a
        // WireGuard interface with no peers, which WireGuard accepts.
        StringBuilder sb = new StringBuilder();
        sb.append("[Interface]\n");
        sb.append("PrivateKey = ").append(privateKey).append('\n');
        sb.append("Address = ").append(address).append('\n');
        if (dns != null && !dns.isBlank()) {
            sb.append("DNS = ").append(dns).append('\n');
        }
        if (mtu != null && mtu > 0) {
            sb.append("MTU = ").append(mtu).append('\n');
        }
        if (listenPort != null && listenPort > 0) {
            sb.append("ListenPort = ").append(listenPort).append('\n');
        }
        for (PeerSpec p : peers) {
            sb.append('\n');
            sb.append("[Peer]\n");
            sb.append("PublicKey = ").append(p.publicKey()).append('\n');
            if (p.allowedIps() != null && !p.allowedIps().isBlank()) {
                sb.append("AllowedIPs = ").append(p.allowedIps()).append('\n');
            }
            if (p.endpoint() != null && !p.endpoint().isBlank()) {
                sb.append("Endpoint = ").append(p.endpoint()).append('\n');
            }
            if (p.persistentKeepalive() != null && p.persistentKeepalive() > 0) {
                sb.append("PersistentKeepalive = ").append(p.persistentKeepalive()).append('\n');
            }
        }
        return sb.toString();
    }
}