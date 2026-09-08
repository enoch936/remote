package com.company.remoteaccess.platform;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ElevationTest {

    @Test
    void elevateCommandWindowsPassesExeAndArgsSeparately() {
        Assumptions.assumeTrue(Os.family() == Os.Family.WINDOWS,
                "Start-Process layout is Windows-specific");
        List<String> command = List.of("C:\\Program Files\\Java\\javaw.exe",
                "-cp", "a;b;c", "com.company.remoteaccess.Launcher", "--fix-requirements");
        Optional<List<String>> cmd = Elevation.elevateCommand(command);
        assertTrue(cmd.isPresent());
        String line = String.join(" ", cmd.get());
        assertTrue(line.contains("Start-Process"), line);
        assertTrue(line.contains("-Verb RunAs"), line);
        assertTrue(line.contains("'C:\\Program Files\\Java\\javaw.exe'"), line);
        assertTrue(!line.contains("''"), "executable must be single-quoted, not double-quoted: " + line);
        assertTrue(line.contains("--fix-requirements"), line);
    }

    @Test
    void elevateCommandRejectsEmptyInput() {
        Assumptions.assumeTrue(Os.family() == Os.Family.WINDOWS);
        assertTrue(Elevation.elevateCommand(List.of()).isEmpty());
        assertTrue(Elevation.elevateCommand(null).isEmpty());
    }

    @Test
    void launchCommandIsExecutableFirstWithLauncherLast() {
        Assumptions.assumeTrue(Os.family() == Os.Family.WINDOWS);
        List<String> parts = Elevation.launchCommand();
        assertTrue(parts.size() >= 4, "expected exe, -cp, classpath, Launcher but got " + parts);
        assertTrue(parts.get(0).endsWith("javaw.exe"), parts.get(0));
        assertTrue(parts.get(parts.size() - 1).endsWith("com.company.remoteaccess.Launcher"),
                parts.get(parts.size() - 1));
    }
}