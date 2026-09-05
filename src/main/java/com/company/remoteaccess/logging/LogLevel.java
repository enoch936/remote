package com.company.remoteaccess.logging;

/** Log severity levels. */
public enum LogLevel {
    TRACE(1), DEBUG(2), INFO(3), WARN(4), ERROR(5), AUDIT(6);

    private final int weight;

    LogLevel(int weight) {
        this.weight = weight;
    }

    public int weight() {
        return weight;
    }

    public boolean isAtLeast(LogLevel threshold) {
        return weight >= threshold.weight;
    }
}