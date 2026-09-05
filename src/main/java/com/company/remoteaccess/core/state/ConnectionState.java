package com.company.remoteaccess.core.state;

/**
 * Explicit connection state machine states (spec section 5).
 *
 * <p>Possible legal transitions:
 *
 * <pre>
 * OFFLINE
 *   -> INITIALIZING -> CHECKING_NETWORK -> AUTHENTICATING -> CONNECTING
 *   -> CONFIGURING -> VERIFYING -> CONNECTED
 *
 * Failure states (reachable from most working states):
 *   ERROR, RETRYING, AUTH_FAILED, SERVER_UNAVAILABLE, NETWORK_UNAVAILABLE,
 *   PERMISSION_REQUIRED, VPN_FAILED
 * All failure states can lead back to OFFLINE (user reset) and to RETRYING.
 * </pre>
 */
public enum ConnectionState {
    OFFLINE,
    INITIALIZING,
    CHECKING_NETWORK,
    AUTHENTICATING,
    CONNECTING,
    CONFIGURING,
    VERIFYING,
    CONNECTED,
    // failure states
    ERROR,
    RETRYING,
    AUTH_FAILED,
    SERVER_UNAVAILABLE,
    NETWORK_UNAVAILABLE,
    PERMISSION_REQUIRED,
    VPN_FAILED;

    public boolean isFailure() {
        return this == ERROR || this == AUTH_FAILED || this == SERVER_UNAVAILABLE
                || this == NETWORK_UNAVAILABLE || this == PERMISSION_REQUIRED || this == VPN_FAILED;
    }

    public boolean isTransient() {
        return !isFailure() && this != OFFLINE && this != CONNECTED;
    }

    public String displayName() {
        String s = name().replace('_', ' ');
        return s.substring(0, 1) + s.substring(1).toLowerCase();
    }

    /** Short uppercase label used by the client dashboard. */
    public String label() {
        return displayName().toUpperCase();
    }
}