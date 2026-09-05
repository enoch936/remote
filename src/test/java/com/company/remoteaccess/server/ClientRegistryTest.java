package com.company.remoteaccess.server;

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

    private static final String PUB_A = "PUB-A-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=";
    private static final String PUB_B = "PUB-B-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=";

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
}