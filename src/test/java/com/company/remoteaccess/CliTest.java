package com.company.remoteaccess;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class CliTest {

    @Test
    void noArgsLaunchesNormally() {
        Cli.Result r = Cli.parse(new String[]{});
        assertEquals(Cli.Action.LAUNCH, r.action());
        assertNull(r.dataDir());
    }

    @Test
    void nullArgsLaunchesNormally() {
        assertEquals(Cli.Action.LAUNCH, Cli.parse(null).action());
    }

    @Test
    void versionFlagPrintsVersion() {
        Cli.Result r = Cli.parse(new String[]{"--version"});
        assertEquals(Cli.Action.VERSION, r.action());
    }

    @Test
    void diagnosticsDefaultsToLocalFile() {
        Cli.Result r = Cli.parse(new String[]{"--diagnostics"});
        assertEquals(Cli.Action.DIAGNOSTICS, r.action());
        assertEquals(Path.of("company-remote-diagnostics.txt"), r.diagnosticsFile());
    }

    @Test
    void diagnosticsAcceptsCustomOutput() {
        Cli.Result r = Cli.parse(new String[]{"--diagnostics", "C:\\tmp\\diag.txt"});
        assertEquals(Path.of("C:\\tmp\\diag.txt"), r.diagnosticsFile());
    }

    @Test
    void dataDirIsCaptured() {
        Cli.Result r = Cli.parse(new String[]{"--data-dir", "C:\\data\\cra"});
        assertEquals(Cli.Action.LAUNCH, r.action());
        assertEquals(Path.of("C:\\data\\cra"), r.dataDir());
    }

    @Test
    void versionAfterDataDirStillVersion() {
        Cli.Result r = Cli.parse(new String[]{"--data-dir", "C:\\x", "--version"});
        assertEquals(Cli.Action.VERSION, r.action());
        assertEquals(Path.of("C:\\x"), r.dataDir());
    }

    @Test
    void flagMissingValuesAreTolerated() {
        Cli.Result r = Cli.parse(new String[]{"--data-dir", "--version"});
        assertEquals(Cli.Action.VERSION, r.action());
        assertNull(r.dataDir());
    }

    @Test
    void diagnosticsHonorsTrailingDataDir() {
        Cli.Result r = Cli.parse(new String[]{"--diagnostics", "diag.txt", "--data-dir", "C:\\x"});
        assertEquals(Cli.Action.DIAGNOSTICS, r.action());
        assertEquals(Path.of("diag.txt"), r.diagnosticsFile());
        assertEquals(Path.of("C:\\x"), r.dataDir());
    }

    @Test
    void unknownArgsIgnored() {
        assertEquals(Cli.Action.LAUNCH, Cli.parse(new String[]{"--frobnicate"}).action());
    }

    @Test
    void fixRequirementsFlagPassesThroughToLaunch() {
        Cli.Result r = Cli.parse(new String[]{"--fix-requirements"});
        assertEquals(Cli.Action.LAUNCH, r.action());
        assertEquals(Cli.Action.LAUNCH,
                Cli.parse(new String[]{"--fix-requirements", "--data-dir", "C:\\x"}).action());
    }
}