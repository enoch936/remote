package com.company.remoteaccess.server;

/** Lifecycle states of the gateway service (server mode). */
public enum GatewayState {
    STOPPED,
    STARTING,
    ONLINE,
    NETWORK_LOST,
    RECOVERING,
    PERMISSION_REQUIRED,
    BINARIES_MISSING,
    NAT_FAILED,
    FIREWALL_FAILED,
    ERROR,
    STOPPING;

    public String displayName() {
        String s = name().replace('_', ' ');
        return s.substring(0, 1) + s.substring(1).toLowerCase();
    }
}