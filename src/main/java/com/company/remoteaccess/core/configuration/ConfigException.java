package com.company.remoteaccess.core.configuration;

import com.company.remoteaccess.networking.IpHelpers;
import com.company.remoteaccess.networking.IpHelpers.Cidr;

import java.util.ArrayList;
import java.util.List;

/** Signalling config problems without leaking details into the UI. */
public class ConfigException extends RuntimeException {

    public enum Kind { INVALID, PARSE_ERROR, NEWER_VERSION, MISSING, STALE }

    private final Kind kind;

    public ConfigException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public ConfigException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }
}