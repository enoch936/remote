package com.company.remoteaccess.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

/**
 * Append-only audit log with hash chaining. Each line references the SHA-256 of
 * the previous line, making silent tampering detectable (does not replace a real
 * SIEM or OS-level security log).
 */
public final class AuditLog {

    private final java.nio.file.Path file;
    private String lastHash = "";

    public AuditLog(java.nio.file.Path file) {
        this.file = file;
    }

    public void append(String actor, String action, String details) {
        try {
            String line = Instant.now().toString() + " | " + actor + " | " + action
                    + " | " + sha256(Secrets.redact(details)) + " | " + lastHash;
            java.nio.file.Files.createDirectories(file.toAbsolutePath().getParent());
            java.nio.file.Files.writeString(file, line + System.lineSeparator(),
                    StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
            lastHash = sha256(line);
        } catch (Exception ignored) {
            // audit must never crash the app
        }
    }

    private static String sha256(String s) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : d) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}