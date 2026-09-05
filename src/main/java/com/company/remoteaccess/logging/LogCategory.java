package com.company.remoteaccess.logging;

/** Structured log categories (spec section 23). */
public enum LogCategory {
    SYSTEM, NETWORK, VPN, AUTH, ROUTING, FIREWALL, CLIENT, SERVER, SECURITY, ERROR, UI;

    public static LogCategory fromString(String s) {
        if (s == null) return SYSTEM;
        try {
            return LogCategory.valueOf(s.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return SYSTEM;
        }
    }
}