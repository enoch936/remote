package com.company.remoteaccess.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PairingTokenTest {

    @Test
    void roundTripsThroughPayload() {
        PairingToken t = new PairingToken("HQ", "gw.example.com", 51820,
                "SERVERPUBKEY12345678901234567890123456789012",
                "10.50.0.9", "tok123");
        PairingToken back = PairingToken.fromPayload(t.toPayload());
        assertEquals(t.serverName(), back.serverName());
        assertEquals(t.serverHost(), back.serverHost());
        assertEquals(t.listenPort(), back.listenPort());
        assertEquals(t.serverPublicKey(), back.serverPublicKey());
        assertEquals(t.assignedClientAddress(), back.assignedClientAddress());
        assertEquals(t.oneTimeToken(), back.oneTimeToken());
    }

    @Test
    void encodesSpecialCharacters() {
        PairingToken t = new PairingToken("HQ & main", "gw.example.com", 51820,
                "k", "10.50.0.2", "token with spaces?");
        PairingToken back = PairingToken.fromPayload(t.toPayload());
        assertEquals("HQ & main", back.serverName());
        assertEquals("token with spaces?", back.oneTimeToken());
    }

    @Test
    void rejectsForeignPayloads() {
        assertThrows(IllegalArgumentException.class,
                () -> PairingToken.fromPayload("https://not-us/"));
    }

    @Test
    void tokenHashIsStableSha256() {
        PairingToken t = new PairingToken("HQ", "h", 51820, "k", "10.50.0.2", "abc");
        assertEquals(64, t.tokenHash().length());
        assertEquals(new PairingToken("HQ", "h", 51820, "k", "10.50.0.2", "abc").tokenHash(),
                t.tokenHash());
    }
}