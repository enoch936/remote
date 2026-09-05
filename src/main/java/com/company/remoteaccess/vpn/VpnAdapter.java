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

    default void setPeer(String tunnelName, String publicKey, String allowedIps) throws VpnException {
        // optional live peer management
    }

    default void removePeer(String tunnelName, String publicKey) throws VpnException {
        // optional live peer management
    }
}