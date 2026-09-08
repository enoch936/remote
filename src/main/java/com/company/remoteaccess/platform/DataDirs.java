package com.company.remoteaccess.platform;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * OS-standard application data directory resolution plus one-time migration
 * from the legacy {@code ~/.company-remote} location.
 *
 * <p>Layout per platform:
 * <ul>
 *   <li>Windows: {@code %APPDATA%\CompanyRemoteAccess}</li>
 *   <li>macOS: {@code ~/Library/Application Support/CompanyRemoteAccess}</li>
 *   <li>Linux/other: {@code ~/.config/company-remote-access}</li>
 * </ul>
 *
 * <p>An explicit override via system property {@code company-remote.data-dir}
 * (used by tests and the {@code --data-dir} CLI flag) always wins.
 */
public final class DataDirs {

    public static final String PROPERTY = "company-remote.data-dir";

    private DataDirs() {
    }

    /** Current process base directory (property override, else OS-standard). */
    public static Path resolveBaseDir() {
        String override = System.getProperty(PROPERTY);
        if (override != null && !override.isBlank()) {
            return Path.of(override);
        }
        return baseDirFor(Os.family(),
                System.getenv("APPDATA"),
                System.getProperty("user.home", "."));
    }

    /** Pure resolution helper (deterministic, testable). */
    public static Path baseDirFor(Os.Family family, String appDataEnv, String userHome) {
        String home = userHome == null || userHome.isBlank() ? "." : userHome;
        switch (family) {
            case WINDOWS:
                if (appDataEnv != null && !appDataEnv.isBlank()) {
                    return Path.of(appDataEnv, "CompanyRemoteAccess");
                }
                return Path.of(home, "AppData", "Roaming", "CompanyRemoteAccess");
            case MACOS:
                return Path.of(home, "Library", "Application Support", "CompanyRemoteAccess");
            case LINUX:
            case OTHER:
            default:
                return Path.of(home, ".config", "company-remote-access");
        }
    }

    /** Legacy location ({@code ~/.company-remote}) used by versions before Phase 2. */
    public static Path legacyBaseDir(String userHome) {
        return Path.of(userHome == null || userHome.isBlank() ? "." : userHome, ".company-remote");
    }

    /** True when migration should run: legacy dir exists and target lacks config.yaml. */
    public static boolean requiresMigration(Path legacy, Path target) {
        return legacy != null && Files.isDirectory(legacy)
                && !Files.exists(target.resolve("config.yaml"));
    }

    /**
     * Move the legacy data directory to the standard location. Returns the number
     * of top-level entries moved. Does nothing when the target already has
     * configuration (avoids clobbering a newer install).
     */
    public static int migrateLegacy(Path legacy, Path target) throws IOException {
        if (!requiresMigration(legacy, target)) {
            return 0;
        }
        Files.createDirectories(target);
        List<Path> entries = new ArrayList<>();
        try (Stream<Path> s = Files.list(legacy)) {
            s.forEach(entries::add);
        }
        int moved = 0;
        for (Path entry : entries) {
            Path dest = target.resolve(entry.getFileName().toString());
            if (Files.exists(dest)) {
                continue;
            }
            Files.move(entry, dest);
            moved++;
        }
        return moved;
    }
}