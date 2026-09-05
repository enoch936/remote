package com.company.remoteaccess.logging;

import java.time.Instant;

/** One structured log entry. */
public record LogEntry(long sequence,
                       Instant timestamp,
                       LogLevel level,
                       LogCategory category,
                       String message) {

    public String format(String pattern) {
        return String.format(pattern, formatTime(), level, category, message);
    }

    private String formatTime() {
        return java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss")
                .withZone(java.time.ZoneId.systemDefault())
                .format(timestamp);
    }

    @Override
    public String toString() {
        return format("%s  %-8s  %-9s  %s");
    }
}