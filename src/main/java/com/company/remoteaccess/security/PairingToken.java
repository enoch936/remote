package com.company.remoteaccess.security;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * A pairing payload passed from server to client (usually via QR code).
 *
 * <p>Contains only non-secret material: discovery metadata and the server's
 * WireGuard public key (identity). The one-time authentication token is the only
 * sensitive field and it is single-use and short-lived.
 */
public record PairingToken(
        String serverName,
        String serverHost,
        int listenPort,
        String serverPublicKey,
        String assignedClientAddress,
        String oneTimeToken) {

    public static final String SCHEME = "company-remote://pair/v1?";

    public String toPayload() {
        return SCHEME + "server=" + enc(serverName)
                + "&host=" + enc(serverHost)
                + "&port=" + listenPort
                + "&pub=" + enc(serverPublicKey)
                + "&client=" + enc(assignedClientAddress == null ? "" : assignedClientAddress)
                + "&token=" + enc(oneTimeToken);
    }

    public static PairingToken fromPayload(String payload) {
        if (payload == null || !payload.startsWith(SCHEME)) {
            throw new IllegalArgumentException("not a company-remote pairing payload");
        }
        String query = payload.substring(SCHEME.length());
        java.util.Map<String, String> params = new java.util.HashMap<>();
        for (String kv : query.split("&")) {
            int i = kv.indexOf('=');
            if (i > 0) {
                params.put(kv.substring(0, i), URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8));
            }
        }
        String serverName = params.get("server");
        String host = params.get("host");
        String port = params.get("port");
        String pub = params.get("pub");
        String client = params.get("client");
        String token = params.get("token");
        if (serverName == null || host == null || host.isEmpty()
                || port == null || pub == null || pub.isEmpty()
                || token == null || token.isEmpty()) {
            throw new IllegalArgumentException("pairing payload is missing fields");
        }
        return new PairingToken(serverName, host, Integer.parseInt(port), pub,
                client == null ? "" : client, token);
    }

    /** Server-side hash of the one-time token (we never store plaintext tokens). */
    public String tokenHash() {
        return Secrets.hash256(oneTimeToken);
    }

    private static String enc(String s) {
        return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8);
    }
}