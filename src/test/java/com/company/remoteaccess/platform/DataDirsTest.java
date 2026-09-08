package com.company.remoteaccess.platform;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DataDirsTest {

    @TempDir
    Path tmp;

    @Test
    void windowsUsesAppDataRoaming() {
        Path p = DataDirs.baseDirFor(Os.Family.WINDOWS,
                "C:\\Users\\Alice\\AppData\\Roaming", "C:\\Users\\Alice");
        assertEquals(Path.of("C:\\Users\\Alice\\AppData\\Roaming", "CompanyRemoteAccess"), p);
    }

    @Test
    void windowsFallsBackToUserHomeWhenNoAppData() {
        Path p = DataDirs.baseDirFor(Os.Family.WINDOWS, null, "C:\\Users\\Bob");
        assertEquals(Path.of("C:\\Users\\Bob", "AppData", "Roaming", "CompanyRemoteAccess"), p);
    }

    @Test
    void macosUsesApplicationSupport() {
        Path p = DataDirs.baseDirFor(Os.Family.MACOS, null, "/home/alice");
        assertEquals(Path.of("/home/alice", "Library", "Application Support", "CompanyRemoteAccess"), p);
    }

    @Test
    void linuxUsesXdgConfig() {
        Path p = DataDirs.baseDirFor(Os.Family.LINUX, null, "/home/alice");
        assertEquals(Path.of("/home/alice", ".config", "company-remote-access"), p);
    }

    @Test
    void propertyOverrideWins() {
        String prev = System.getProperty(DataDirs.PROPERTY);
        try {
            System.setProperty(DataDirs.PROPERTY, tmp.resolve("override").toString());
            assertEquals(tmp.resolve("override"), DataDirs.resolveBaseDir());
        } finally {
            if (prev == null) {
                System.clearProperty(DataDirs.PROPERTY);
            } else {
                System.setProperty(DataDirs.PROPERTY, prev);
            }
        }
    }

    @Test
    void legacyIsUnderUserHome() {
        assertEquals(Path.of("/home/alice", ".company-remote"),
                DataDirs.legacyBaseDir("/home/alice"));
    }

    @Test
    void migrationMovesFilesAndIsIdempotent() throws Exception {
        Path legacy = tmp.resolve("legacy");
        Path target = tmp.resolve("target");
        Files.createDirectories(legacy.resolve("data"));
        Files.writeString(legacy.resolve("config.yaml"), "mode: CLIENT\n");
        Files.createDirectories(legacy.resolve("vpn"));
        Files.writeString(legacy.resolve("vpn").resolve("pub.key"), "B".repeat(43) + "=");

        assertTrue(DataDirs.requiresMigration(legacy, target));
        assertEquals(3, DataDirs.migrateLegacy(legacy, target));

        assertTrue(Files.exists(target.resolve("config.yaml")));
        assertTrue(Files.exists(target.resolve("data")));
        assertTrue(Files.exists(target.resolve("vpn").resolve("pub.key")));
        assertFalse(Files.exists(legacy.resolve("config.yaml")));

        assertEquals(0, DataDirs.migrateLegacy(legacy, target));
        assertFalse(DataDirs.requiresMigration(legacy, target));
    }

    @Test
    void migrationSkippedWhenTargetHasConfig() throws Exception {
        Path legacy = tmp.resolve("legacy");
        Path target = tmp.resolve("target");
        Files.createDirectories(legacy);
        Files.writeString(legacy.resolve("config.yaml"), "mode: CLIENT\n");
        Files.createDirectories(target);
        Files.writeString(target.resolve("config.yaml"), "mode: SERVER\n");

        assertFalse(DataDirs.requiresMigration(legacy, target));
        assertEquals(0, DataDirs.migrateLegacy(legacy, target));
        assertTrue(Files.exists(legacy.resolve("config.yaml")));
    }

    @Test
    void emptyOrNullHomeDefaultsToCurrentDirectory() {
        assertEquals(Path.of(".", ".config", "company-remote-access"),
                DataDirs.baseDirFor(Os.Family.LINUX, null, null));
        assertEquals(Path.of(".", ".config", "company-remote-access"),
                DataDirs.baseDirFor(Os.Family.LINUX, null, "  "));
    }
}