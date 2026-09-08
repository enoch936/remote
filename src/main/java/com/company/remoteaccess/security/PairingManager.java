package com.company.remoteaccess.security;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;

/**
 * Server-side pairing token management.
 *
 * <p>Tokens are single-use and short-lived (default 10 minutes). Only the hash of
 * a token, the device name and the client's WireGuard public key it was bound to
 * are retained. The token binds the public key the administrator typed; it is
 * consumed when a WireGuard handshake proves that the client really owns that key
 * (the application is zero-HTTP, so the handshake itself is the proof). Failed
 * attempts are rate-limited to deter brute force.
 */
public final class PairingManager {

    private static final class Issued {
        final String deviceName;
        final String clientPublicKey;
        final Instant expires;

        Issued(String deviceName, String clientPublicKey, Instant expires) {
            this.deviceName = deviceName;
            this.clientPublicKey = clientPublicKey;
            this.expires = expires;
        }
    }

    private final Object lock = new Object();
    private final Map<String, Issued> issued = new HashMap<>();
    private final Duration ttl;
    private final AuditLog audit;

    // simple per-minute rate limiter keyed by caller hint
    private final Map<String, int[]> attempts = new HashMap<>();

    public PairingManager(Duration ttl) {
        this(ttl, null);
    }

    public PairingManager(Duration ttl, AuditLog audit) {
        this.ttl = ttl == null ? Duration.ofMinutes(10) : ttl;
        this.audit = audit;
    }

    /**
     * Issue a single-use pairing token bound to {@code deviceName}.
     *
     * @param deviceName human-readable client device name claimed during pairing
     * @return fresh one-time token; only its hash is kept server-side
     */
    public String issue(String deviceName) {
        return issue(deviceName, null);
    }

    /**
     * Issue a single-use pairing token bound to {@code deviceName} and the client
     * public key the administrator pasted. The token is consumed when the owning
     * client completes its first WireGuard handshake ({@link #claimForHandshake}).
     *
     * @param deviceName     human-readable client device name
     * @param clientPublicKey the WireGuard public key pasted into the pair dialog
     * @return fresh one-time token; only its hash is kept server-side
     */
    public String issue(String deviceName, String clientPublicKey) {
        Validation.requireDeviceName(deviceName, "device name");
        if (clientPublicKey != null) {
            Validation.requireWireGuardKey(clientPublicKey, "client public key");
        }
        String token = Secrets.randomToken();
        String safeName = deviceName.trim();
        synchronized (lock) {
            issued.put(Secrets.hash256(token),
                    new Issued(safeName, clientPublicKey, Instant.now().plus(ttl)));
        }
        audit("pairing", "token_issued",
                "device=" + safeName + " bound_to_pasted_key=" + (clientPublicKey != null));
        AppLogger.getLogger().info(LogCategory.AUTH,
                "pairing token issued for '%s' (ttl %ds, single-use, bound to pasted key)",
                safeName, ttl.getSeconds());
        return token;
    }

    /**
     * Verify and consume a pairing attempt.
     *
     * @param token      the presented one-time token (plaintext; hashed before compare)
     * @param deviceName device name claimed by the client, must match the binding
     * @param remoteHint stable caller identifier used for rate limiting
     */
    public boolean verifyAndConsume(String token, String deviceName, String remoteHint) {
        if (!allowAttempt(remoteHint)) {
            AppLogger.getLogger().warn(LogCategory.AUTH, "pairing attempt rate-limited (%s)", remoteHint);
            return false;
        }
        if (token == null || token.isEmpty()) {
            return false;
        }
        Issued candidate;
        synchronized (lock) {
            candidate = issued.remove(Secrets.hash256(token));
        }
        if (candidate == null) {
            AppLogger.getLogger().warn(LogCategory.AUTH, "pairing token rejected (unknown or reused)");
            return false;
        }
        if (Instant.now().isAfter(candidate.expires)) {
            AppLogger.getLogger().warn(LogCategory.AUTH, "pairing token expired");
            return false;
        }
        String safeName = deviceName == null ? "" : deviceName;
        if (!Secrets.constantEquals(safeName, candidate.deviceName)) {
            AppLogger.getLogger().warn(LogCategory.AUTH,
                    "pairing device name mismatch (claimed '%s')", safeName);
            return false;
        }
        audit("pairing", "token_verified", "device=" + candidate.deviceName);
        AppLogger.getLogger().info(LogCategory.AUTH, "pairing verified for '%s'", safeName);
        return true;
    }

    /**
     * Consume the pending pairing token whose bound public key has completed its
     * first WireGuard handshake. The handshake proves the client owns that key, so
     * this is the zero-HTTP equivalent of "verify and mark used".
     *
     * @param clientPublicKey the handshaken peer's WireGuard public key
     * @return the device name bound to that token, if one was pending and unexpired
     */
    public Optional<String> claimForHandshake(String clientPublicKey) {
        if (clientPublicKey == null || clientPublicKey.isBlank()) {
            return Optional.empty();
        }
        synchronized (lock) {
            Iterator<Map.Entry<String, Issued>> it = issued.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<String, Issued> e = it.next();
                Issued candidate = e.getValue();
                if (!clientPublicKey.equals(candidate.clientPublicKey)) {
                    continue;
                }
                it.remove();
                if (Instant.now().isAfter(candidate.expires)) {
                    AppLogger.getLogger().warn(LogCategory.AUTH,
                            "pairing token for '%s' expired before its first handshake",
                            candidate.deviceName);
                    return Optional.empty();
                }
                AppLogger.getLogger().info(LogCategory.AUTH,
                        "pairing verified for '%s' on first handshake (token consumed once)",
                        candidate.deviceName);
                audit("pairing", "token_consumed",
                        "device=" + candidate.deviceName + " first_handshake");
                return Optional.of(candidate.deviceName);
            }
        }
        return Optional.empty();
    }

    public int activeCount() {
        synchronized (lock) {
            issued.entrySet().removeIf(e -> Instant.now().isAfter(e.getValue().expires));
            return issued.size();
        }
    }

    private boolean allowAttempt(String remoteHint) {
        String key = remoteHint == null ? "unknown" : remoteHint;
        synchronized (attempts) {
            String bucket = "m" + (System.currentTimeMillis() / 60_000);
            int[] w = attempts.computeIfAbsent(key + bucket, k -> new int[]{0});
            w[0]++;
            if (attempts.size() > 10_000) {
                attempts.clear();
            }
            return w[0] <= 10;
        }
    }

    private void audit(String actor, String action, String details) {
        if (audit != null) {
            audit.append(actor, action, details);
        }
    }
}