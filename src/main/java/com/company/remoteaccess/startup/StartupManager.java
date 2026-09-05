package com.company.remoteaccess.startup;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.platform.CommandResult;
import com.company.remoteaccess.platform.CommandRunner;
import com.company.remoteaccess.platform.Os;

/**
 * OS-level "start with the operating system" support.
 *
 * <p>Windows: HKCU Run key (no elevation). Linux/macOS: XDG autostart file.
 * Also exposes a helper to register a scheduled task / systemd unit for the
 * gateway when the operator explicitly wants a real background service.
 */
public final class StartupManager {

    private static final String APP_NAME = "CompanyRemoteAccess";

    private final CommandRunner runner;

    public StartupManager(CommandRunner runner) {
        this.runner = runner;
    }

    public void apply(boolean startWithOs) {
        if (startWithOs) {
            enable();
        } else {
            disable();
        }
    }

    public void enable() {
        switch (Os.family()) {
            case WINDOWS -> enableWindows();
            default -> enableXdg();
        }
    }

    public void disable() {
        switch (Os.family()) {
            case WINDOWS -> disableWindows();
            default -> disableXdg();
        }
    }

    public boolean isEnabled() {
        return switch (Os.family()) {
            case WINDOWS -> {
                CommandResult r = runner.run("reg", "query",
                        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "/v", APP_NAME);
                yield r.success();
            }
            default -> java.nio.file.Files.exists(
                    java.nio.file.Path.of(System.getProperty("user.home"),
                            ".config", "autostart", "company-remote-access.desktop"));
        };
    }

    private void enableWindows() {
        String command = launchCommand();
        CommandResult r = runner.run("reg", "add",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "/v", APP_NAME, "/t", "REG_SZ", "/d", command, "/f");
        AppLogger.getLogger().info(LogCategory.SYSTEM,
                r.success() ? "auto-start enabled (registry)" : "auto-start enable failed: " + r.stderr());
    }

    private void disableWindows() {
        CommandResult r = runner.run("reg", "delete",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "/v", APP_NAME, "/f");
        AppLogger.getLogger().info(LogCategory.SYSTEM,
                "auto-start disabled (registry)");
    }

    private void enableXdg() {
        try {
            var path = java.nio.file.Path.of(System.getProperty("user.home"),
                    ".config", "autostart", "company-remote-access.desktop");
            java.nio.file.Files.createDirectories(path.getParent());
            String cmd = launchCommand();
            java.nio.file.Files.writeString(path,
                    "[Desktop Entry]\nType=Application\nName=Company Remote Access\nExec="
                            + cmd + "\nX-GNOME-Autostart-enabled=true\n");
            AppLogger.getLogger().info(LogCategory.SYSTEM, "auto-start enabled (XDG autostart)");
        } catch (java.io.IOException e) {
            AppLogger.getLogger().warn(LogCategory.SYSTEM, "auto-start enable failed: %s", e.getMessage());
        }
    }

    private void disableXdg() {
        try {
            java.nio.file.Files.deleteIfExists(
                    java.nio.file.Path.of(System.getProperty("user.home"),
                            ".config", "autostart", "company-remote-access.desktop"));
            AppLogger.getLogger().info(LogCategory.SYSTEM, "auto-start disabled (XDG autostart)");
        } catch (java.io.IOException e) {
            AppLogger.getLogger().warn(LogCategory.SYSTEM, "auto-start disable failed: %s", e.getMessage());
        }
    }

    /**
     * The exact command used to launch the app at log-on. Respects the value
     * jpackage writes into {@code app-path} when running a packaged build.
     */
    public static String launchCommand() {
        String appPath = System.getProperty("jpackage.app-path", "");
        if (!appPath.isBlank()) {
            return '"' + appPath + '"';
        }
        String javaHome = System.getProperty("java.home");
        String javaBin = javaHome + java.io.File.separator + "bin" + java.io.File.separator
                + (Os.isWindows() ? "javaw.exe" : "java");
        String classpath = System.getProperty("java.class.path", ".");
        return '"' + javaBin + "\" -cp \"" + classpath + "\" com.company.remoteaccess.Launcher";
    }
}