package com.company.remoteaccess.server;

import com.company.remoteaccess.security.AuditLog;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientRegistryTest {

    @TempDir
    Path tmp;

    private static final String PUB_A = "A".repeat(43) + "=";
    private static final String PUB_B = "B".repeat(43) + "=";

    @Test
    void addAuthorizedAndCount() {
        ClientRegistry r = new ClientRegistry(tmp.resolve("peers.json"));
        assertEquals(0, r.countAuthorized());
        r.add("laptop", PUB_A, "10.50.0.2");
        r.add("desktop", PUB_B, "10.50.0.3");
        assertEquals(2, r.countAuthorized());
        assertEquals(Optional.of("laptop"), r.findByPublicKey(PUB_A).map(d -> d.deviceName));
    }

    @Test
    void duplicatePublicKeyRejected() {
        ClientRegistry r = new ClientRegistry(tmp.resolve("peers.json"));
        r.add("laptop", PUB_A, "10.50.0.2");
        assertThrows(IllegalArgumentException.class,
                () -> r.add("other", PUB_A, "10.50.0.5"));
    }

    @Test
    void persistsAndReloads() throws Exception {
        Path file = tmp.resolve("peers.json");
        ClientRegistry r = new ClientRegistry(file);
        r.add("laptop", PUB_A, "10.50.0.2");

        ClientRegistry reloaded = new ClientRegistry(file);
        List<ServerPeer> peers = reloaded.all();
        assertEquals(1, peers.size());
        assertEquals("laptop", peers.get(0).deviceName);
        assertEquals(PUB_A, peers.get(0).publicKey);
        assertEquals("10.50.0.2", peers.get(0).vpnAddress);
        assertTrue(Files.exists(file));
    }

    @Test
    void revokeHidesFromAuthorized() {
        ClientRegistry r = new ClientRegistry(tmp.resolve("peers.json"));
        r.add("laptop", PUB_A, "10.50.0.2");
        r.revoke("laptop");
        assertEquals(0, r.countAuthorized());
        // revoked entries remain listed (for audit history) but are no longer authorized
        assertEquals(1, r.all().size());
        assertTrue(r.all().stream().anyMatch(d -> d.status == ServerPeer.Status.REVOKED));
    }

    @Test
    void renameAndLastSeen() {
        ClientRegistry r = new ClientRegistry(tmp.resolve("peers.json"));
        r.add("laptop", PUB_A, "10.50.0.2");
        r.rename("laptop", "john-laptop");
        assertTrue(r.findByName("john-laptop").isPresent());
        r.markOnline("john-laptop");
        assertTrue(r.findByName("john-laptop").get().lastSeenAt != null);
    }

    @Test
    void listenerFiresOnChanges() throws Exception {
        ClientRegistry r = new ClientRegistry(tmp.resolve("peers.json"));
        int[] fired = {0};
        r.addListener(devices -> fired[0]++);
        r.add("laptop", PUB_A, "10.50.0.2");
        r.remove("laptop");
        assertEquals(2, fired[0]);
    }

    @Test
    void revokedAddressIsFreedForReuse() {
        ClientRegistry r = new ClientRegistry(tmp.resolve("peers.json"));
        r.add("laptop", PUB_A, "10.50.0.2");
        r.revoke("laptop");
        r.add("phone", PUB_B, "10.50.0.2");
        assertEquals(1, r.countAuthorized());
        assertTrue(r.findByPublicKey(PUB_B).isPresent());
    }

    @Test
    void revokedKeyCanNeverBeReused() {
        ClientRegistry r = new ClientRegistry(tmp.resolve("peers.json"));
        r.add("laptop", PUB_A, "10.50.0.2");
        r.revoke("laptop");
        assertThrows(IllegalArgumentException.class,
                () -> r.add("other", PUB_A, "10.50.0.9"));
    }

    @Test
    void renameRejectsInvalidName() {
        ClientRegistry r = new ClientRegistry(tmp.resolve("peers.json"));
        r.add("laptop", PUB_A, "10.50.0.2");
        assertThrows(IllegalArgumentException.class,
                () -> r.rename("laptop", "bad/name"));
        assertTrue(r.findByName("laptop").isPresent());
    }

    @Test
    void blockSuspendsAndUnblockRestores() {
        ClientRegistry r = new ClientRegistry(tmp.resolve("peers.json"));
        r.add("laptop", PUB_A, "10.50.0.2");
        r.block("laptop");
        assertEquals(0, r.countAuthorized());
        assertTrue(r.all().stream().anyMatch(d -> d.status == ServerPeer.Status.BLOCKED));
        assertEquals(Optional.of("10.50.0.2"),
                r.all().stream().filter(d -> d.deviceName.equals("laptop"))
                        .map(d -> d.vpnAddress).findFirst());

        r.unblock("laptop");
        assertEquals(1, r.countAuthorized());
        assertTrue(r.all().stream().anyMatch(d -> d.status == ServerPeer.Status.AUTHORIZED));
    }

    @Test
    void blockStatusPersistsAndKeepsAddressReserved() {
        Path file = tmp.resolve("peers.json");
        ClientRegistry r = new ClientRegistry(file);
        r.add("laptop", PUB_A, "10.50.0.2");
        r.block("laptop");

        ClientRegistry reloaded = new ClientRegistry(file);
        assertEquals(0, reloaded.countAuthorized());
        assertTrue(reloaded.all().stream().anyMatch(d -> d.status == ServerPeer.Status.BLOCKED));
        assertThrows(IllegalArgumentException.class,
                () -> reloaded.add("other", PUB_B, "10.50.0.2"));
    }

    @Test
    void blockUnblockAreAudited() throws Exception {
        Path auditFile = tmp.resolve("audit.log");
        ClientRegistry r = new ClientRegistry(tmp.resolve("peers.json"), new AuditLog(auditFile));
        r.add("laptop", PUB_A, "10.50.0.2");
        r.block("laptop");
        r.unblock("laptop");

        String joined = String.join("\n", Files.readAllLines(auditFile));
        assertTrue(joined.contains("device_blocked"));
        assertTrue(joined.contains("device_unblocked"));
        assertTrue(new AuditLog(auditFile).verifyChain());
    }
}