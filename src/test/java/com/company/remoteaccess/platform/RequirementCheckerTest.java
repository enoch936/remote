package com.company.remoteaccess.platform;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RequirementCheckerTest {

    @Test
    void unsupportedOsIsReported() {
        var req = byId(RequirementChecker.evaluate(false, true, true, true, true), "os");
        assertEquals(RequirementChecker.Status.UNSUPPORTED, req.status());
    }

    @Test
    void missingWireGuardIsReported() {
        var req = byId(RequirementChecker.evaluate(true, false, true, true, true), "wg");
        assertEquals(RequirementChecker.Status.MISSING, req.status());
        assertTrue(req.detail().toLowerCase().contains("not found"));
    }

    @Test
    void elevationPermissionWhenAdminRequired() {
        var req = byId(RequirementChecker.evaluate(true, true, false, true, true), "elevation");
        assertEquals(RequirementChecker.Status.PERMISSION, req.status());
        assertTrue(req.detail().contains("restart"));
    }

    @Test
    void elevationNotRequiredWhenAdminNotNeeded() {
        var req = byId(RequirementChecker.evaluate(true, true, false, false, true), "elevation");
        assertEquals(RequirementChecker.Status.OK, req.status());
    }

    @Test
    void missingConfigIsReported() {
        var req = byId(RequirementChecker.evaluate(true, true, true, true, false), "config");
        assertEquals(RequirementChecker.Status.MISSING, req.status());
    }

    @Test
    void allOkWhenEverythingPresent() {
        var rules = RequirementChecker.evaluate(true, true, true, true, true);
        for (var r : rules) {
            assertEquals(RequirementChecker.Status.OK, r.status(), r.id());
        }
    }

    @Test
    void surveyFindsWireGuardThroughRunner() {
        var rules = RequirementChecker.survey(new FakeRunner(), "", true, true);
        assertEquals(RequirementChecker.Status.OK, byId(rules, "wg").status());
        assertEquals(RequirementChecker.Status.OK, byId(rules, "os").status());
    }

    @Test
    void summarizeIsFlatOneLiner() {
        String s = RequirementChecker.summarize(
                RequirementChecker.evaluate(true, false, false, true, false));
        assertTrue(s.contains("os=ok"));
        assertTrue(s.contains("wg=missing"));
        assertTrue(s.contains("elevation=permission"));
        assertTrue(s.contains("config=missing"));
    }

    private static RequirementChecker.Requirement byId(List<RequirementChecker.Requirement> rules, String id) {
        return rules.stream().filter(r -> r.id().equals(id)).findFirst().orElseThrow();
    }

    static class FakeRunner extends CommandRunner {
        @Override
        public CommandResult run(String... command) {
            if (command.length >= 1 && (command[0].endsWith("where.exe") || command[0].endsWith("which"))) {
                return new CommandResult(0, "C:\\Program Files\\WireGuard\\wg.exe", "");
            }
            return new CommandResult(1, "", "not found");
        }

        @Override
        public CommandResult run(List<String> command, long timeoutSeconds) {
            return run(command.toArray(new String[0]));
        }
    }
}