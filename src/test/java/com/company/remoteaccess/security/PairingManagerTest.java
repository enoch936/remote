package com.company.remoteaccess.security;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PairingManagerTest {

    @Test
    void issuedTokenVerifiesOnce() {
        PairingManager pm = new PairingManager(Duration.ofMinutes(10));
        String token = pm.issue("john-laptop");
        assertTrue(pm.verifyAndConsume(token, "john-laptop", "127.0.0.1"));
        // single use
        assertFalse(pm.verifyAndConsume(token, "john-laptop", "127.0.0.1"));
    }

    @Test
    void unknownTokenRejected() {
        PairingManager pm = new PairingManager(Duration.ofMinutes(10));
        assertFalse(pm.verifyAndConsume("not-issued", "john-laptop", "127.0.0.1"));
    }

    @Test
    void expiredTokenRejected() {
        PairingManager pm = new PairingManager(Duration.ofMillis(1));
        String token = pm.issue("dev");
        try {
            Thread.sleep(5);
        } catch (InterruptedException ignored) {
        }
        assertFalse(pm.verifyAndConsume(token, "dev", "127.0.0.1"));
    }

    @Test
    void deviceNameMismatchRejected() {
        PairingManager pm = new PairingManager(Duration.ofMinutes(10));
        String token = pm.issue("real-name");
        assertFalse(pm.verifyAndConsume(token, "other-name", "127.0.0.1"));
    }

    @Test
    void bruteForceIsRateLimitedPerMinute() {
        PairingManager pm = new PairingManager(Duration.ofMinutes(10));
        for (int i = 0; i < 10; i++) {
            pm.verifyAndConsume("garbage-" + i, "x", "attacker");
        }
        // the 11th attempt in the same minute must be rejected by the limiter
        assertFalse(pm.verifyAndConsume("garbage-10", "x", "attacker"));
    }

    @Test
    void activeCountTracksIssued() {
        PairingManager pm = new PairingManager(Duration.ofMinutes(10));
        assertEquals(0, pm.activeCount());
        pm.issue("a");
        pm.issue("b");
        assertEquals(2, pm.activeCount());
    }
}