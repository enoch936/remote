package com.company.remoteaccess.security;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Server-side pairing token management.
 *
 * <p>Tokens are single-use and short-lived (default 10 minutes). Only the hash of
 * a token and the device name it was bound to are retained. Failed attempts are
 * rate-limited to deter brute force.
 */
public final class PairingManager {

    private static final class Issued {
        final String deviceName;
        final Instant expires;

        Issued(String deviceName, Instant expires) {
            this.deviceName = deviceName;
            this.expires = expires;
        }
    }

    private final Object lock = new Object();
    private final Map<String, Issued> issued = new HashMap<>();
    private final Duration ttl;

    // simple per-minute rate limiter keyed by caller hint
    private final Map<String, int[]> attempts = new HashMap<>();

    public PairingManager(Duration ttl) {
        this.ttl = ttl == null ? Duration.ofMinutes(10) : ttl;
    }

    /**
     * Issue a single-use pairing token bound to {@code deviceName}.
     *
     * @param deviceName human-readable client device name claimed during pairing
     * @return fresh one-time token; only its hash is kept server-side
     */
    public String issue(String deviceName) {
        String token = Secrets.randomToken();
        String safeName = deviceName == null ? "" : deviceName;
        synchronized (lock) {
            issued.put(Secrets.hash256(token), new Issued(safeName, Instant.now().plus(ttl)));
        }
        AppLogger.getLogger().info(LogCategory.AUTH,
                "pairing token issued for '%s' (ttl %ds, single-use)", safeName, ttl.getSeconds());
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
        AppLogger.getLogger().info(LogCategory.AUTH, "pairing verified for '%s'", safeName);
        return true;
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
}