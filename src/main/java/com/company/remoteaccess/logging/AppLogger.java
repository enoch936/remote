package com.company.remoteaccess.logging;

import com.company.remoteaccess.security.Secrets;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

/**
 * Structured application logger.
 *
 * <p>Responsibilities:
 * <ul>
 *   <li>tagged categories (NETWORK, VPN, AUTH, ...)</li>
 *   <li>in-memory ring buffer for the UI log pane</li>
 *   <li>optional file writer that rolls over at a size limit</li>
 *   <li>automatic redaction of secrets, keys and pairing tokens</li>
 * </ul>
 */
public final class AppLogger {

    public interface Sink {
        void accept(LogEntry entry);
    }

    private static final AppLogger INSTANCE = new AppLogger();

    private final AtomicLong sequence = new AtomicLong();
    private final List<Sink> sinks = new CopyOnWriteArrayList<>();
    private final List<LogEntry> ring = new ArrayList<>();
    private final Object ringLock = new Object();
    private volatile Path logFile;
    private volatile long maxFileBytes = 10L * 1024 * 1024;
    private volatile LogLevel threshold = LogLevel.INFO;

    public static AppLogger getLogger() {
        return INSTANCE;
    }

    public void addSink(Sink sink) {
        sinks.add(sink);
    }

    public void setFile(Path file) {
        this.logFile = file;
        Path parent = file.toAbsolutePath().getParent();
        if (parent != null) {
            try {
                Files.createDirectories(parent);
            } catch (IOException ignored) {
                // non-fatal
            }
        }
    }

    public void setThreshold(LogLevel level) {
        this.threshold = level == null ? LogLevel.INFO : level;
    }

    public List<LogEntry> snapshot() {
        synchronized (ringLock) {
            return new ArrayList<>(ring);
        }
    }

    public void log(LogCategory category, LogLevel level, String message) {
        if (!level.isAtLeast(threshold)) {
            return;
        }
        String safe = Secrets.redact(message);
        LogEntry entry = new LogEntry(sequence.incrementAndGet(), Instant.now(), level, category, safe);
        synchronized (ringLock) {
            ring.add(entry);
            if (ring.size() > 4000) {
                ring.remove(0);
            }
        }
        if (logFile != null) {
            writeToFile(entry);
        }
        for (Sink s : sinks) {
            try {
                s.accept(entry);
            } catch (RuntimeException ignored) {
                // a bad sink must never break logging
            }
        }
    }

    private void writeToFile(LogEntry entry) {
        try {
            Path file = logFile;
            if (Files.exists(file) && Files.size(file) > maxFileBytes) {
                roll(file);
            }
            Files.createDirectories(file.toAbsolutePath().getParent());
            Files.writeString(file, entry.toString() + System.lineSeparator(),
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {
            // best effort
        }
    }

    private void roll(Path file) throws IOException {
        int i = 1;
        while (Files.exists(file.resolveSibling(file.getFileName() + "." + i))) {
            i++;
        }
        Files.move(file, file.resolveSibling(file.getFileName() + "." + i));
    }

    // ----- convenience facade -----

    public void info(LogCategory category, Supplier<String> message) {
        log(category, LogLevel.INFO, message.get());
    }

    public void info(LogCategory category, String message, Object... args) {
        log(category, LogLevel.INFO, format(message, args));
    }

    public void warn(LogCategory category, String message, Object... args) {
        log(category, LogLevel.WARN, format(message, args));
    }

    public void error(LogCategory category, Throwable t, String message, Object... args) {
        String msg = format(message, args);
        if (t != null) {
            StringWriter sw = new StringWriter();
            t.printStackTrace(new PrintWriter(sw));
            msg = msg + "\n" + Secrets.redact(sw.toString());
        }
        log(category, LogLevel.ERROR, msg);
    }

    public void error(LogCategory category, String message, Object... args) {
        log(category, LogLevel.ERROR, format(message, args));
    }

    public void debug(LogCategory category, String message, Object... args) {
        log(category, LogLevel.DEBUG, format(message, args));
    }

    /** Alias kept for the state machine's simple calls. */
    public void debug(String category, String message, Object... args) {
        log(LogCategory.fromString(category), LogLevel.DEBUG, format(message, args));
    }

    public void info(String category, String message, Object... args) {
        log(LogCategory.fromString(category), LogLevel.INFO, format(message, args));
    }

    public void error(String category, Throwable t, String message, Object... args) {
        error(LogCategory.fromString(category), t, message, args);
    }

    public void error(String category, String message, Object... args) {
        error(LogCategory.fromString(category), (Throwable) null, message, args);
    }

    private static String format(String message, Object... args) {
        if (args == null || args.length == 0) {
            return message;
        }
        try {
            return String.format(message, args);
        } catch (RuntimeException e) {
            return message;
        }
    }
}