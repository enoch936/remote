package com.company.remoteaccess.vpn;

/** Abstraction over the underlying secure VPN implementation (WireGuard). */
public interface VpnAdapter {

    /** Verify the tunnel binaries are present and runnable. */
    void ensureAvailable() throws VpnException;

    /** Stage the tunnel configuration in the application-managed store. */
    void writeConfig(String tunnelName, String configText) throws VpnException;

    /** Move the staged configuration into the VPN tooling (service/system config). */
    void loadConfig(String tunnelName) throws VpnException;

    void start(String tunnelName) throws VpnException;

    void stop(String tunnelName) throws VpnException;

    /** Fully remove the installed tunnel configuration (reconfiguration/uninstall). */
    void removeConfig(String tunnelName) throws VpnException;

    VpnStatus status(String tunnelName);

    /** Whether the tunnel is installed (service present / interface config in place). */
    default boolean isInstalled(String tunnelName) {
        return false;
    }

    /** Whether the tunnel interface/service is currently running. */
    default boolean isRunning(String tunnelName) {
        VpnStatus s = status(tunnelName);
        return s != null && s.running();
    }

    /**
     * Idempotent install: no-op when the tunnel already exists. Repeated calls
     * must never attempt a redundant installation.
     */
    default void ensureInstalled(String tunnelName) throws VpnException {
        if (!isInstalled(tunnelName)) {
            loadConfig(tunnelName);
        }
    }

    /**
     * Idempotent bring-up: reuse an already-running tunnel, otherwise install
     * if needed and start it. Repeated calls are safe.
     */
    default void ensureRunning(String tunnelName) throws VpnException {
        if (isRunning(tunnelName)) {
            return;
        }
        if (!isInstalled(tunnelName)) {
            ensureInstalled(tunnelName);
        }
        start(tunnelName);
    }

    /** Optional post-start verification that the running tunnel is the expected one. */
    default void verifyConfig(String tunnelName) throws VpnException {
    }

    default void setPeer(String tunnelName, String publicKey, String allowedIps) throws VpnException {
        // optional live peer management
    }

    default void removePeer(String tunnelName, String publicKey) throws VpnException {
        // optional live peer management
    }
}