package com.company.remoteaccess.security;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Read-side view over the tamper-evident audit log for the in-UI audit viewer.
 * Parses raw lines into entries, reports chain status and renders a readable
 * block of the most recent events. Details were hashed at write time, so what
 * the UI shows can never leak secrets.
 */
public final class AuditView {

    public record Entry(String timestamp, String actor, String action, String detailHash) {

        static Entry parse(String line) {
            String[] parts = line.split(" \\| ", 5);
            if (parts.length < 4) {
                return new Entry(line, "?", "raw", "");
            }
            return new Entry(parts[0], parts[1], parts[2], parts[3].length() > 12
                    ? parts[3].substring(0, 12) + "\u2026" : parts[3]);
        }
    }

    private AuditView() {
    }

    /** True when the on-disk hash chain is intact (missing log is treated as intact). */
    public static boolean verified(Path file) {
        return AuditLog.verifyChain(file);
    }

    /** The most recent {@code max} entries in chronological order. */
    public static List<Entry> read(Path file, int max) {
        if (file == null) {
            return List.of();
        }
        List<Entry> out = new ArrayList<>();
        for (String line : new AuditLog(file).tail(max)) {
            out.add(Entry.parse(line));
        }
        return out;
    }

    /** Human-readable rendering of entries (one per line, newest first). */
    public static String render(List<Entry> entries) {
        StringBuilder sb = new StringBuilder();
        for (int i = entries.size() - 1; i >= 0; i--) {
            Entry e = entries.get(i);
            sb.append(e.timestamp())
                    .append("  ").append(e.actor())
                    .append("  ").append(e.action());
            if (!e.detailHash().isEmpty()) {
                sb.append("  [" + e.detailHash() + "]");
            }
            sb.append('\n');
        }
        return sb.toString();
    }
}