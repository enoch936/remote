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
     * Return a command that re-launches {@code command} (an executable followed
     * by its arguments) with elevation, or empty when elevation is not available
     * on this platform. The executable and each argument are passed separately so
     * paths containing spaces survive elevation.
     */
    public static java.util.Optional<java.util.List<String>> elevateCommand(
            java.util.List<String> command) {
        if (command == null || command.isEmpty()) {
            return java.util.Optional.empty();
        }
        String executable = command.get(0);
        java.util.List<String> args = command.subList(1, command.size());
        switch (Os.family()) {
            case WINDOWS -> {
                String argumentList = args.isEmpty() ? "''"
                        : args.stream().map(Elevation::psQuote)
                                .collect(java.util.stream.Collectors.joining(", "));
                return java.util.Optional.of(java.util.List.of(
                        "powershell", "-NoProfile", "-Command",
                        "Start-Process -Verb RunAs -FilePath " + psQuote(executable)
                                + " -ArgumentList " + argumentList));
            }
            case LINUX -> {
                java.util.List<String> cmd = new java.util.ArrayList<>();
                cmd.add("pkexec");
                cmd.addAll(command);
                return java.util.Optional.of(cmd);
            }
            case MACOS -> {
                String shell = command.stream().map(Elevation::shQuote)
                        .collect(java.util.stream.Collectors.joining(" "));
                return java.util.Optional.of(java.util.List.of("osascript",
                        "-e", "do shell script \"" + shell + "\" with administrator privileges"));
            }
            default -> {
                return java.util.Optional.empty();
            }
        }
    }

    private static String psQuote(String s) {
        return "'" + s.replace("'", "''") + "'";
    }

    private static String shQuote(String s) {
        return "'" + s.replace("'", "'\"'\"'") + "'";
    }

    // ------------------------------------------------------------------
    // elevated-start handshake
    //
    // A non-elevated instance relaunches itself elevated (UAC/pkexec/...) and must
    // not shut down until the elevated window is really on screen. The elevated
    // instance writes a marker file at startup; the original instance polls it.
    // ------------------------------------------------------------------

    public static java.nio.file.Path startedMarkerPath() {
        return java.nio.file.Path.of(System.getProperty("java.io.tmpdir", "."),
                "company-remote-elevated.marker");
    }

    public static void clearStartedMarker() {
        try {
            java.nio.file.Files.deleteIfExists(startedMarkerPath());
        } catch (Exception ignored) {
            // best effort
        }
    }

    /** Called by an elevated instance as soon as it boots. */
    public static void markStarted() {
        try {
            java.nio.file.Files.writeString(startedMarkerPath(),
                    String.valueOf(System.currentTimeMillis()));
        } catch (Exception ignored) {
            // best effort — shutdown only waits and times out otherwise
        }
    }

    public static boolean startedMarkerPresent() {
        return java.nio.file.Files.exists(startedMarkerPath());
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

    /** Whether this platform can re-launch processes elevated at all. */
    public static boolean canElevate() {
        return switch (Os.family()) {
            case WINDOWS, LINUX, MACOS -> true;
            default -> false;
        };
    }

    /**
     * Re-launch this application itself with administrator privileges, passing
     * {@code extraArgs} (e.g. {@code --data-dir}). Returns true when the elevated
     * process was started. The caller should then exit this instance.
     */
    public static boolean relaunchElevated(java.util.List<String> extraArgs) {
        if (!canElevate() || isElevated()) {
            return false;
        }
        java.util.List<String> full = new java.util.ArrayList<>(launchCommand());
        if (extraArgs != null) {
            full.addAll(extraArgs);
        }
        java.util.Optional<java.util.List<String>> cmd = elevateCommand(full);
        if (cmd.isEmpty()) {
            return false;
        }
        try {
            new ProcessBuilder(cmd.get()).start();
            return true;
        } catch (Exception e) {
            AppLogger.getLogger().error(LogCategory.SYSTEM, e,
                    "failed to relaunch with elevation: %s", e.getMessage());
            return false;
        }
    }

    /**
     * Re-launch command for the running application (executable first, then
     * arguments), respecting the packaged app-path.
     */
    public static java.util.List<String> launchCommand() {
        String appPath = System.getProperty("jpackage.app-path", "");
        if (!appPath.isBlank()) {
            return java.util.List.of(appPath);
        }
        String javaBin = System.getProperty("java.home") + java.io.File.separator + "bin"
                + java.io.File.separator + (Os.isWindows() ? "javaw.exe" : "java");
        String classpath = System.getProperty("java.class.path", ".");
        return java.util.List.of(javaBin, "-cp", classpath, "com.company.remoteaccess.Launcher");
    }
}