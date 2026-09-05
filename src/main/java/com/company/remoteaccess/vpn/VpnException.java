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
            case UNSUPPORTED_PLATFORM -> "This platform is not supported by the VPN adapter yet.";
            default -> "Review the log for details and retry.";
        };
    }
}