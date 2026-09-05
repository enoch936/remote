package com.company.remoteaccess.vpn;

import java.util.List;

/** Snapshot of the running (or not-running) VPN tunnel. */
public record VpnStatus(
        String tunnelName,
        boolean running,
        String publicKey,
        int listenPort,
        String privateKeyOrNull,
        List<VpnPeer> peers) {

    public static VpnStatus down(String tunnelName) {
        return new VpnStatus(tunnelName, false, null, 0, null, List.of());
    }

    /** True when at least one peer has had a recent handshake. */
    public boolean healthy() {
        return running && peers.stream().anyMatch(p -> p.handshaken()
                && p.latestHandshakeSecondsAgo() < 120);
    }
}