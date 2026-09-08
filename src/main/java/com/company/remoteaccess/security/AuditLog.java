package com.company.remoteaccess.security;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Append-only audit log with hash chaining. Each line references the SHA-256 of
 * the previous line, making silent tampering detectable (does not replace a real
 * SIEM or OS-level security log). Details are never persisted — only the SHA-256
 * of their redacted form is stored, so secrets cannot leak into the audit trail.
 */
public final class AuditLog {

    private final Path file;
    private String lastHash = "";

    public AuditLog(Path file) {
        this.file = file;
    }

    public void append(String actor, String action, String details) {
        if (actor == null || actor.isBlank() || action == null || action.isBlank()) {
            return;
        }
        try {
            String line = Instant.now().toString() + " | " + actor + " | " + action
                    + " | " + sha256(Secrets.redact(details)) + " | " + lastHash;
            Files.createDirectories(file.toAbsolutePath().getParent());
            Files.writeString(file, line + System.lineSeparator(),
                    StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
            lastHash = sha256(line);
        } catch (Exception ignored) {
            // audit must never crash the app
        }
    }

    /**
     * Last {@code max} entries in chronological order. Empty when the log is
     * missing or unreadable.
     */
    public List<String> tail(int max) {
        List<String> lines = readLines();
        if (max <= 0 || lines.isEmpty()) {
            return List.of();
        }
        return lines.size() <= max ? lines : List.copyOf(lines.subList(lines.size() - max, lines.size()));
    }

    /** Re-verify the hash chain of this log file from disk. */
    public boolean verifyChain() {
        return verifyChain(file);
    }

    /**
     * Verify the tamper-evident hash chain of an audit log file. Every line must
     * carry the SHA-256 of the full previous line as its final {@code " | "}
     * segment; the first line must carry an empty previous hash.
     */
    public static boolean verifyChain(Path file) {
        List<String> lines;
        try {
            if (file == null || !Files.exists(file)) {
                return true;
            }
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return false;
        }
        String previous = null;
        for (String line : lines) {
            if (line.isEmpty()) {
                continue;
            }
            String expected = previous == null ? "" : sha256OrNull(previous);
            if (expected == null) {
                return false;
            }
            int sep = line.lastIndexOf(" | ");
            String recorded = sep < 0 ? line : line.substring(sep + 3);
            if (!expected.equals(recorded)) {
                return false;
            }
            previous = line;
        }
        return true;
    }

    private List<String> readLines() {
        try {
            if (file == null || !Files.exists(file)) {
                return List.of();
            }
            List<String> all = Files.readAllLines(file, StandardCharsets.UTF_8);
            List<String> out = new ArrayList<>();
            for (String l : all) {
                if (!l.isEmpty()) {
                    out.add(l);
                }
            }
            return out;
        } catch (Exception e) {
            return List.of();
        }
    }

    private static String sha256OrNull(String s) {
        try {
            return sha256(s);
        } catch (NoSuchAlgorithmException e) {
            return null;
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