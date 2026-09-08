package com.company.remoteaccess.vpn;

import com.company.remoteaccess.core.authentication.ClientIdentity;
import com.company.remoteaccess.core.configuration.AppConfig;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * VpnManager tunnel orchestration is idempotent: repeated configuration and
 * bring-up calls never trigger a redundant install or restart.
 */
class VpnManagerIdempotencyTest {

    /** Deterministic, recording VpnAdapter double. */
    static class RecordingAdapter implements VpnAdapter {
        int writes;
        int installs;
        int starts;
        int stops;
        int verifies;
        boolean installed;
        boolean running;

        @Override
        public void ensureAvailable() {
        }

        @Override
        public void writeConfig(String tunnelName, String configText) {
            writes++;
        }

        @Override
        public void loadConfig(String tunnelName) {
            installed = true;
            installs++;
        }

        @Override
        public void start(String tunnelName) {
            running = true;
            starts++;
        }

        @Override
        public void stop(String tunnelName) {
            running = false;
            stops++;
        }

        @Override
        public void removeConfig(String tunnelName) {
            installed = false;
            running = false;
        }

        @Override
        public VpnStatus status(String tunnelName) {
            return new VpnStatus(tunnelName, running, null, 0, null, List.of());
        }

        @Override
        public boolean isInstalled(String tunnelName) {
            return installed;
        }

        @Override
        public boolean isRunning(String tunnelName) {
            return running;
        }

        @Override
        public void verifyConfig(String tunnelName) {
            verifies++;
        }
    }

    private VpnManager manager(RecordingAdapter adapter, boolean available) {
        return new VpnManager(adapter, () -> AppConfig.create(), null, null, null, null, null,
                available);
    }

    @Test
    void repeatedConfigureNeverReinstalls() throws VpnException {
        RecordingAdapter adapter = new RecordingAdapter();
        VpnManager manager = manager(adapter, true);
        manager.ensureTunnelConfigured("company0", "conf-a");
        manager.ensureTunnelConfigured("company0", "conf-b");
        assertEquals(2, adapter.writes);
        assertEquals(1, adapter.installs, "second configure must reuse the installed tunnel");
    }

    @Test
    void repeatedBringUpWhenRunningOnlyVerifies() throws VpnException {
        RecordingAdapter adapter = new RecordingAdapter();
        adapter.installed = true;
        adapter.running = true;
        VpnManager manager = manager(adapter, true);
        manager.ensureTunnelRunning("company0");
        manager.ensureTunnelRunning("company0");
        assertEquals(0, adapter.starts, "already-running tunnel must never be restarted");
        assertEquals(0, adapter.installs);
        assertEquals(2, adapter.verifies);
    }

    @Test
    void bringUpInstallsOnceThenReuses() throws VpnException {
        RecordingAdapter adapter = new RecordingAdapter();
        VpnManager manager = manager(adapter, true);
        manager.ensureTunnelRunning("company0");
        manager.ensureTunnelRunning("company0");
        assertEquals(1, adapter.installs);
        assertEquals(1, adapter.starts, "second bring-up while running must not start again");
        assertEquals(1, adapter.verifies);
    }

    @Test
    void unavailableEngineIsControlledNoOp() {
        RecordingAdapter adapter = new RecordingAdapter();
        VpnManager manager = manager(adapter, false);
        VpnException ex = assertThrows(VpnException.class,
                () -> manager.startGateway(List.of(new ClientIdentity("d", "k", "10.0.0.2"))));
        assertEquals(VpnException.Kind.BINARIES_MISSING, ex.kind());
        assertEquals(0, adapter.writes);
        assertEquals(0, adapter.installs);
        assertFalse(manager.status().running());
        assertEquals(VpnStatus.down("company0"), manager.stopTunnel());
        manager.addPeerToRunning("k", "10.0.0.2");
        assertEquals(0, adapter.starts);
    }
}