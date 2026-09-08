package com.company.remoteaccess.core.configuration;

import com.company.remoteaccess.core.configuration.ConfigValidator.Issue;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The un-paired client state must stay navigable: the setup wizard (not a fatal
 * startup error) is where pairing happens.
 */
class ConfigValidatorClientStateTest {

    private static List<Issue> errors(List<Issue> issues) {
        return issues.stream().filter(i -> i.severity == Issue.Severity.ERROR).toList();
    }

    @Test
    void blankClientEndpointIsNotAnErrorWhenNeverPaired() {
        AppConfig cfg = AppConfig.create(); // mode CLIENT, no endpoint, not paired
        List<Issue> issues = ConfigValidator.validate(cfg);
        assertTrue(errors(issues).isEmpty(), "un-paired client should only warn: " + errors(issues));
        assertTrue(issues.stream().anyMatch(i ->
                i.severity == Issue.Severity.WARNING && i.message.contains("pair the device")));
    }

    @Test
    void missingEndpointAfterPairingIsAnError() {
        AppConfig cfg = AppConfig.create().with("client.pairApplied", true);
        List<Issue> issues = ConfigValidator.validate(cfg);
        assertTrue(errors(issues).stream().anyMatch(i -> i.message.contains("re-pair")),
                "expected a re-pair error, got: " + errors(issues));
    }

    @Test
    void invalidEndpointIsAnError() {
        AppConfig cfg = AppConfig.create()
                .with("client.serverEndpoint", "not an address");
        List<Issue> issues = ConfigValidator.validate(cfg);
        assertTrue(errors(issues).stream().anyMatch(i -> i.message.contains("invalid")),
                "expected an invalid-endpoint error, got: " + errors(issues));
    }

    @Test
    void blankServerHostIsOnlyAWarning() {
        AppConfig cfg = AppConfig.create().with("mode", "SERVER");
        List<Issue> issues = ConfigValidator.validate(cfg);
        assertFalse(errors(issues).stream().anyMatch(i -> i.message.contains("hostname")),
                "blank server host must remain a warning");
    }
}