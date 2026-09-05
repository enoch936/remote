package com.company.remoteaccess.networking;

/** Networking-specific failure with an actionable kind. */
public class NetworkException extends Exception {

    public enum Kind {
        PERMISSION_REQUIRED,
        NOT_CONFIGURED,
        INTERFACE_NOT_FOUND,
        UNSUPPORTED_PLATFORM,
        COMMAND_FAILED,
        TIMEOUT,
        NOT_ONLINE
    }

    private final Kind kind;

    public NetworkException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public NetworkException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }
}