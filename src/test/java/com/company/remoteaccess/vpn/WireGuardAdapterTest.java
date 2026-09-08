package com.company.remoteaccess.vpn;

import com.company.remoteaccess.platform.CommandResult;
import com.company.remoteaccess.platform.CommandRunner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WireGuardAdapterTest {

    @TempDir
    Path tmp;

    @Test
    void parseInterfacesSplitsWhitespaceLines() {
        assertEquals(List.of("wg0", "company0"),
                WireGuardAdapter.parseInterfaces("wg0\ncompany0\n\n"));
        assertEquals(List.of(), WireGuardAdapter.parseInterfaces(null));
        assertEquals(List.of(), WireGuardAdapter.parseInterfaces(""));
    }

    @Test
    void tunnelAlreadyUpMatchesExactNameOnly() {
        assertTrue(WireGuardAdapter.tunnelAlreadyUp(List.of("company0", "wg0"), "company0"));
        assertFalse(WireGuardAdapter.tunnelAlreadyUp(List.of("company0", "wg0"), "company"));
        assertFalse(WireGuardAdapter.tunnelAlreadyUp(List.of(), "company0"));
        assertFalse(WireGuardAdapter.tunnelAlreadyUp(null, "company0"));
        assertFalse(WireGuardAdapter.tunnelAlreadyUp(List.of("company0"), null));
    }

    @Test
    void listTunnelsDelegatesToWgShowInterfaces() {
        CommandRunner runner = new CommandRunner() {
            @Override
            public CommandResult run(String... command) {
                if (command.length == 3 && command[0].endsWith("wg")
                        && "show".equals(command[1]) && "interfaces".equals(command[2])) {
                    return new CommandResult(0, "wg0\ncompany0\n", "");
                }
                return new CommandResult(1, "", "unexpected");
            }
        };
        WireGuardAdapter adapter = new WireGuardAdapter(runner, tmp, "wg", null, null);
        assertEquals(List.of("wg0", "company0"), adapter.listTunnels());
    }

    @Test
    void listTunnelsIsEmptyWhenShowFails() {
        CommandRunner runner = new CommandRunner() {
            @Override
            public CommandResult run(String... command) {
                return new CommandResult(1, "", "wg not found");
            }
        };
        WireGuardAdapter adapter = new WireGuardAdapter(runner, tmp, "wg", null, null);
        assertEquals(List.of(), adapter.listTunnels());
    }
}