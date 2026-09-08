package com.company.remoteaccess.security;

import com.company.remoteaccess.networking.IpHelpers;

import java.util.regex.Pattern;

/**
 * Strict, side-effect-free input validation used at every security boundary:
 * WireGuard public/private keys, endpoints, device names, DNS lists and ports.
 *
 * <p>Anything malformed is rejected with a {@code field} prefix so callers can
 * build useful error messages without ever feeding raw user input into shell
 * commands or generated WireGuard configuration.
 */
public final class Validation {

    private static final Pattern WG_KEY =
            Pattern.compile("^[A-Za-z0-9+/]{43}=$");

    private static final Pattern IPV4 =
            Pattern.compile("^\\d{1,3}(?:\\.\\d{1,3}){3}$");

    // RFC-1035 hostname with a numeric TLD excluded; also rejects IPv4 literals.
    private static final Pattern HOSTNAME = Pattern.compile(
            "^(?=.{1,253}$)(?!.*-$)(?!^-)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z]{2,63}$");

    private static final Pattern CONTROLS = Pattern.compile("[\\u0000-\\u001f\\u007f]");

    private static final Pattern DNS_TOKEN =
            Pattern.compile("^\\d{1,3}(?:\\.\\d{1,3}){3}$");

    private Validation() {
    }

    // ------------------------------------------------------------------
    // WireGuard keys (32-byte base64; always 44 chars ending with '=')
    // ------------------------------------------------------------------

    public static boolean isWireGuardKey(String key) {
        return key != null && WG_KEY.matcher(key).matches();
    }

    public static void requireWireGuardKey(String key, String field) {
        if (!isWireGuardKey(key)) {
            throw new IllegalArgumentException(field
                    + " must be a WireGuard key (44 base64 chars ending with '=')");
        }
    }

    // ------------------------------------------------------------------
    // endpoints (host[:port]), IPv4 or hostname
    // ------------------------------------------------------------------

    public static boolean isValidEndpoint(String endpoint) {
        if (endpoint == null || endpoint.isBlank() || endpoint.indexOf(' ') >= 0) {
            return false;
        }
        String host = endpoint;
        int port = -1;
        int colon = endpoint.lastIndexOf(':');
        if (colon >= 0) {
            host = endpoint.substring(0, colon);
            String portText = endpoint.substring(colon + 1);
            if (portText.isEmpty() || !portText.chars().allMatch(Character::isDigit)) {
                return false;
            }
            try {
                port = Integer.parseInt(portText);
            } catch (NumberFormatException e) {
                return false;
            }
        }
        if (host.isBlank() || !isIpv4(host) && !isHostname(host)) {
            return false;
        }
        return colon < 0 || port >= 1 && port <= 65535;
    }

    public static void requireEndpoint(String endpoint, String field) {
        if (!isValidEndpoint(endpoint)) {
            throw new IllegalArgumentException(field
                    + " must be a hostname or IPv4 address, optionally with a UDP port (1-65535)");
        }
    }

    public static boolean isHostname(String host) {
        if (host == null || host.isBlank()) {
            return false;
        }
        // allow a single trailing dot (fully-qualified form)
        String h = host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
        return HOSTNAME.matcher(h).matches();
    }

    public static boolean isIpv4(String ip) {
        if (ip == null || !IPV4.matcher(ip).matches()) {
            return false;
        }
        try {
            IpHelpers.parseIp(ip);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public static boolean isHostnameOrIpv4(String value) {
        return isIpv4(value) || isHostname(value);
    }

    // ------------------------------------------------------------------
    // device names
    // ------------------------------------------------------------------

    public static boolean isValidDeviceName(String name) {
        if (name == null || name.isBlank()) {
            return false;
        }
        String n = name.trim();
        if (n.length() > 64) {
            return false;
        }
        if (CONTROLS.matcher(n).find()) {
            return false;
        }
        // block characters that are dangerous in filesystem paths, shell
        // quoting or JSON payloads (apostrophes are common in names and safe)
        for (int i = 0; i < n.length(); i++) {
            char c = n.charAt(i);
            if ("/\";`;{}<>|\\".indexOf(c) >= 0) {
                return false;
            }
        }
        return true;
    }

    public static void requireDeviceName(String name, String field) {
        if (!isValidDeviceName(name)) {
            throw new IllegalArgumentException(field
                    + " must be 1-64 characters and may not contain / \\ ; \" ` { } < > or |");
        }
    }

    // ------------------------------------------------------------------
    // DNS address lists (comma/space separated IPv4)
    // ------------------------------------------------------------------

    public static boolean isValidDnsList(String dns) {
        if (dns == null || dns.isBlank()) {
            return false;
        }
        for (String t : dns.split("[,;\\s]+")) {
            if (t.isBlank()) {
                continue;
            }
            if (!DNS_TOKEN.matcher(t).matches()) {
                return false;
            }
            try {
                IpHelpers.parseIp(t);
            } catch (IllegalArgumentException e) {
                return false;
            }
        }
        return true;
    }

    public static void requireDnsList(String dns, String field) {
        if (dns != null && !dns.isBlank() && !isValidDnsList(dns)) {
            throw new IllegalArgumentException(field
                    + " must be a comma-separated list of valid IP addresses");
        }
    }

    // ------------------------------------------------------------------

    public static void requirePort(int port, String field) {
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException(field + " must be between 1 and 65535");
        }
    }
}