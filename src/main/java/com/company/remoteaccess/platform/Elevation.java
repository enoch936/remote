package com.company.remoteaccess.platform;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;

/**
 * Elevation utilities. The application requests administrator privileges only for
 * operations that genuinely require them (VPN interface, routing, firewall, NAT,
 * forwarding, service registration) and never for routine operations.
 */
public final class Elevation {

    private Elevation() {
    }

    public static boolean isElevated() {
        return switch (Os.family()) {
            case WINDOWS -> isWindowsElevated();
            case LINUX, MACOS -> isRoot();
            default -> false;
        };
    }

    private static boolean isRoot() {
        return "0".equals(System.getProperty("user.name", ""));
    }

    private static boolean isWindowsElevated() {
        try {
            ProcessBuilder pb = new ProcessBuilder("whoami", "/groups");
            Process p = pb.start();
            String output = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(20, java.util.concurrent.TimeUnit.SECONDS);
            // SID S-1-16-12288 == High Mandatory Level (elevated)
            return output.contains("S-1-16-12288");
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Return a command that re-launches the given arguments with elevation, or
     * empty when elevation is not available on this platform.
     */
    public static java.util.Optional<java.util.List<String>> elevateCommand(
            String executable, java.util.List<String> args) {
        switch (Os.family()) {
            case WINDOWS -> {
                return java.util.Optional.of(java.util.List.of(
                        "powershell", "-NoProfile", "-Command",
                        "Start-Process -Verb RunAs -Wait -FilePath '" + executable
                                + "' -ArgumentList '" + String.join(" ", args) + "'"));
            }
            case LINUX -> {
                return java.util.Optional.of(java.util.List.of("pkexec", executable));
            }
            case MACOS -> {
                return java.util.Optional.of(java.util.List.of("osascript",
                        "-e", "do shell script \"" + executable + "\" with administrator privileges"));
            }
            default -> {
                return java.util.Optional.empty();
            }
        }
    }

    /** Human-readable hint shown when elevation is missing. */
    public static String requiredHint(String operation) {
        return switch (Os.family()) {
            case WINDOWS -> "Restart the application as Administrator to " + operation + ".";
            case LINUX, MACOS -> "Run the application with sudo to " + operation + ".";
            default -> operation;
        };
    }

    public static void logHint(String operation) {
        AppLogger.getLogger().warn(LogCategory.SYSTEM,
                "Administrator privileges are required to %s. %s", operation, requiredHint(operation));
    }
}