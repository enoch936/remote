package com.company.remoteaccess.vpn;

/** VPN-specific failure with an actionable kind. */
public class VpnException extends Exception {

    public enum Kind {
        BINARIES_MISSING,
        PERMISSION_REQUIRED,
        CONFIGURATION_ERROR,
        START_FAILED,
        NOT_RUNNING,
        UNSUPPORTED_PLATFORM,
        TIMEOUT,
        NAT_CONFIGURATION,
        FIREWALL_CONFIGURATION,
        INTERNAL
    }

    private final Kind kind;

    public VpnException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public VpnException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }

    /** Human guidance shown to the user (no raw error codes). */
    public String actionHint() {
        return switch (kind) {
            case BINARIES_MISSING -> "Install WireGuard from wireguard.com and install the driver, then retry.";
            case PERMISSION_REQUIRED ->
                    "Administrator privileges are required. Restart the application with elevation.";
            case NAT_CONFIGURATION ->
                    "Full-tunnel NAT could not be enabled. Check that IP forwarding is on and the company LAN interface is correct.";
            case FIREWALL_CONFIGURATION ->
                    "The firewall rule could not be applied. Check that the application is running with administrator privileges.";
            case UNSUPPORTED_PLATFORM -> "This platform is not supported by the VPN adapter yet.";
            default -> "Review the log for details and retry.";
        };
    }
}