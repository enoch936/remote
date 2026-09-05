package com.company.remoteaccess.vpn;

import java.util.List;

/** Parsed status of one VPN peer. */
public record VpnPeer(
        String publicKey,
        String endpoint,
        List<String> allowedIps,
        long latestHandshakeSecondsAgo,
        long rxBytes,
        long txBytes) {

    public boolean handshaken() {
        return latestHandshakeSecondsAgo >= 0;
    }
}