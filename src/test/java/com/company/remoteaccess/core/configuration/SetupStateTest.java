package com.company.remoteaccess.core.configuration;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * First-run decision rules: the setup wizard must complete once; legacy configs
 * written before the marker only count when a seat is genuinely ready.
 */
class SetupStateTest {

    @Test
    void freshDefaultIsNotSetup() {
        AppConfig cfg = AppConfig.create();
        assertFalse(cfg.setupDone());
        assertFalse(AppConfig.isSetupComplete(cfg, false, false));
    }

    @Test
    void completedWizardIsAlwaysSetup() {
        AppConfig done = AppConfig.create().with("app.setupDone", true);
        assertEquals(true, done.setupDone());
        // even a bare client / keyless server with the marker counts as complete
        assertTrue(AppConfig.isSetupComplete(done, false, false));
        assertTrue(AppConfig.isSetupComplete(done, true, true));
    }

    @Test
    void legacyClientCountsOnlyWhenPairedWithEndpoint() {
        AppConfig plainClient = AppConfig.create();
        assertFalse(AppConfig.isSetupComplete(plainClient, false, true));

        AppConfig paired = plainClient
                .with("client.pairApplied", true)
                .with("client.serverEndpoint", "gw.example.com:51820");
        assertTrue(AppConfig.isSetupComplete(paired, true, true));
    }

    @Test
    void legacyClientPairFlagWithoutEndpointIsNotReady() {
        AppConfig half = AppConfig.create().with("client.pairApplied", true);
        assertFalse(AppConfig.isSetupComplete(half, false, true));
    }

    @Test
    void serverRoleIgnoresClientReadiness() {
        AppConfig server = AppConfig.create().with("mode", "SERVER");
        assertFalse(AppConfig.isSetupComplete(server, true, false));
        assertTrue(AppConfig.isSetupComplete(server, true, true));
    }

    @Test
    void nullConfigIsNeverSetup() {
        assertFalse(AppConfig.isSetupComplete(null, true, true));
    }
}