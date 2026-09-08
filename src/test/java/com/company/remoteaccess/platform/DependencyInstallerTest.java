package com.company.remoteaccess.platform;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DependencyInstallerTest {

    @Test
    void windowsUsesWingetWhenPresent() {
        Assumptions.assumeTrue(Os.family() == Os.Family.WINDOWS,
                "winget plan layout is Windows-specific on a fake runner");
        var plan = DependencyInstaller.wireGuardInstallPlan(new WingetPresentRunner());
        assertTrue(plan.isPresent());
        assertTrue(plan.get().automatic());
        assertTrue(plan.get().requiresElevation());
        assertFalse(plan.get().command().isEmpty());
        List<String> cmd = plan.get().command();
        assertEquals("winget", cmd.get(0));
        assertTrue(cmd.contains("--id"));
        assertTrue(cmd.contains("WireGuard.WireGuard"));
    }

    @Test
    void windowsFallsBackToManualWhenNoWinget() {
        Assumptions.assumeTrue(Os.family() == Os.Family.WINDOWS,
                "manual fallback layout is Windows-specific");
        var plan = DependencyInstaller.wireGuardInstallPlan(new NoToolingRunner());
        assertTrue(plan.isPresent());
        assertFalse(plan.get().automatic());
    }

    @Test
    void linuxUsesAptOrDnf() {
        Assumptions.assumeTrue(Os.family() == Os.Family.LINUX);
        var plan = DependencyInstaller.wireGuardInstallPlan(new NoToolingRunner());
        assertTrue(plan.isPresent());
        assertTrue(String.join(" ", plan.get().command())
                .contains("wireguard-tools"));
    }

    @Test
    void macUsesHomebrew() {
        Assumptions.assumeTrue(Os.family() == Os.Family.MACOS);
        var plan = DependencyInstaller.wireGuardInstallPlan(new NoToolingRunner());
        assertTrue(plan.isPresent());
        assertEquals("brew", plan.get().command().get(0));
    }

    @Test
    void manualHintIsNeverBlank() {
        assertFalse(DependencyInstaller.manualHint().isBlank());
    }

    static class WingetPresentRunner extends CommandRunner {
        @Override
        public CommandResult run(String... command) {
            if (command.length == 2 && "winget".equals(command[0])) {
                return new CommandResult(0, "v1.6", "");
            }
            return new CommandResult(127, "", "not found");
        }
    }

    static class NoToolingRunner extends CommandRunner {
        @Override
        public CommandResult run(String... command) {
            return new CommandResult(127, "", "not found");
        }
    }
}