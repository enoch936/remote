package com.company.remoteaccess.core.state;

/** The operating role of this installation. */
public enum Role {
    /** Runs on the company/office network and acts as the encrypted gateway. */
    SERVER,
    /** Runs on a home/remote computer and connects to the company gateway. */
    CLIENT;

    public static Role fromString(String value) {
        if (value == null) {
            throw new IllegalArgumentException("role must not be null");
        }
        return Role.valueOf(value.trim().toUpperCase());
    }
}