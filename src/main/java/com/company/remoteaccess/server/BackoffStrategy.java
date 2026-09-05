package com.company.remoteaccess.server;

/** Pure exponential-backoff strategy with jitter, used by server and client. */
public final class BackoffStrategy {

    private final long baseDelayMs;
    private final long maxDelayMs;
    private final int maxRetries;
    private final long jitterMs;

    public BackoffStrategy(long baseDelayMs, long maxDelayMs, int maxRetries, long jitterMs) {
        this.baseDelayMs = baseDelayMs;
        this.maxDelayMs = maxDelayMs;
        this.maxRetries = Math.max(1, maxRetries);
        this.jitterMs = jitterMs;
    }

    public int maxRetries() {
        return maxRetries;
    }

    /**
     * Delay before retry {@code attempt+1}, where {@code attempt} starts at 0.
     * Adds non-deterministic jitter so restart storms are avoided.
     */
    public long nextDelayMs(int attempt) {
        if (attempt < 0) {
            attempt = 0;
        }
        if (attempt > maxRetries) {
            return -1; // give up
        }
        long exp = baseDelayMs << Math.min(attempt, 10);
        long capped = Math.min(exp, maxDelayMs);
        long jitter = jitterMs <= 0 ? 0 : (long) (Math.random() * jitterMs);
        return capped + jitter;
    }
}