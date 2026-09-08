package com.company.remoteaccess.vpn;

import com.company.remoteaccess.core.authentication.ClientIdentity;

import java.util.List;

/**
 * The narrow contract the gateway controller needs from a VPN engine. Extracted
 * so {@code GatewayService} concurrency/lifecycle behavior can be tested with a
 * deterministic double without OS-level commands; {@link VpnManager} is the
 * production implementation.
 */
public interface GatewayVpn {

    /** Whether the WireGuard tooling is present and verified in order to run. */
    boolean isAvailable();

    /** Bring the server gateway fully up for the given authorized peers. */
    VpnStatus startGateway(List<ClientIdentity> authorizedPeers) throws VpnException;

    /** Best-effort tunnel stop; never throws. */
    VpnStatus stopTunnel();

    /** Current tunnel status. */
    VpnStatus status();

    /** Add an authorized peer to the running interface without a restart. */
    void addPeerToRunning(String publicKey, String vpnAddress);

    /** Remove temporary route/forwarding/networking changes applied by this gateway. */
    void removeAllManagedNetworking();

    /** Remove every firewall rule this gateway created. */
    void removeAllManagedFirewall();

    /** Remove the NAT state this gateway applied. */
    void removeAllManagedNat();
}