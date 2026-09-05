package com.company.remoteaccess.platform;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Restricts file and directory permissions to the current account using the
 * operating system's own tools (Windows {@code icacls}, POSIX chmod).
 */
public final class FilePermissions {

    private FilePermissions() {
    }

    public static void hardenFile(Path file) throws IOException {
        AppLogger.getLogger().debug(LogCategory.SECURITY, "hardening permissions for %s", file);
        CommandRunner runner = new CommandRunner();
        switch (Os.family()) {
            case WINDOWS -> {
                CommandResult r = runner.run(command(
                        "icacls", file.toAbsolutePath().toString(),
                        "/inheritance:r", "/grant:r", currentUserSid() + ":(F)"));
                if (r.failed()) {
                    AppLogger.getLogger().warn(LogCategory.SECURITY,
                            "icacls hardening of %s failed: %s", file, r.stderr());
                }
            }
            default -> {
                CommandResult r = runner.run(command("chmod", "600", file.toAbsolutePath().toString()));
                if (r.failed()) {
                    AppLogger.getLogger().warn(LogCategory.SECURITY,
                            "chmod hardening of %s failed: %s", file, r.stderr());
                }
            }
        }
    }

    public static void hardenDirectory(Path dir) throws IOException {
        if (!Files.isDirectory(dir)) {
            Files.createDirectories(dir);
        }
        AppLogger.getLogger().debug(LogCategory.SECURITY, "hardening directory %s", dir);
        CommandRunner runner = new CommandRunner();
        switch (Os.family()) {
            case WINDOWS -> {
                CommandResult r = runner.run(command(
                        "icacls", dir.toAbsolutePath().toString(),
                        "/inheritance:r", "/grant:r", currentUserSid() + ":(OI)(CI)F"));
                if (r.failed()) {
                    // non-fatal on some Windows setups; the directory is inside the user profile
                    AppLogger.getLogger().warn(LogCategory.SECURITY,
                            "icacls hardening of %s failed: %s", dir, r.stderr());
                }
            }
            default -> {
                CommandResult r = runner.run(command("chmod", "700", dir.toAbsolutePath().toString()));
                if (r.failed()) {
                    AppLogger.getLogger().warn(LogCategory.SECURITY,
                            "chmod hardening of %s failed: %s", dir, r.stderr());
                }
            }
        }
    }

    private static String currentUserSid() {
        try {
            var pb = new ProcessBuilder("whoami", "/user");
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(20, java.util.concurrent.TimeUnit.SECONDS);
            for (String line : out.split("\\r?\\n")) {
                int i = line.indexOf("S-1-");
                if (i >= 0) {
                    String sid = line.substring(i).trim();
                    int sp = sid.indexOf(' ');
                    return sp > 0 ? sid.substring(0, sp) : sid;
                }
            }
        } catch (Exception ignored) {
            // fall through
        }
        return System.getProperty("user.name", "Everyone");
    }

    private static java.util.List<String> command(String... parts) {
        return java.util.Arrays.asList(parts);
    }
}