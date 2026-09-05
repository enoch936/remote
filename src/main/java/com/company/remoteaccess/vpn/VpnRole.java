package com.company.remoteaccess.vpn;

/** Types of tunnel configuration this application can produce. */
public enum VpnRole {
    /** Server/gateway side listens for inbound peers. */
    GATEWAY,
    /** Client/home side dials the gateway. */
    CLIENT
}