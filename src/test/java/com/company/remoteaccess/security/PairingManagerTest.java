package com.company.remoteaccess.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PairingManagerTest {

    @TempDir
    Path tmp;

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

    private static final String KEY_JOHN = "C".repeat(43) + "=";
    private static final String KEY_OTHER = "D".repeat(43) + "=";

    @Test
    void tokenConsumedWhenBoundKeyHandshakes() {
        PairingManager pm = new PairingManager(Duration.ofMinutes(10));
        String token = pm.issue("john-laptop", KEY_JOHN);
        // unknown key is not claimed
        assertEquals(java.util.Optional.empty(), pm.claimForHandshake(KEY_OTHER));
        // first handshake of the bound key consumes the token once
        assertEquals(java.util.Optional.of("john-laptop"),
                pm.claimForHandshake(KEY_JOHN));
        assertEquals(0, pm.activeCount());
        // reusing the same key after consumption yields nothing
        assertEquals(java.util.Optional.empty(), pm.claimForHandshake(KEY_JOHN));
        assertTrue(token != null && token.length() >= 32);
    }

    @Test
    void expiredTokenNotClaimedOnHandshake() {
        PairingManager pm = new PairingManager(Duration.ofMillis(1));
        pm.issue("dev", KEY_OTHER);
        try {
            Thread.sleep(5);
        } catch (InterruptedException ignored) {
        }
        assertEquals(java.util.Optional.empty(), pm.claimForHandshake(KEY_OTHER));
    }

    @Test
    void rejectsMalformedDeviceNameAndKey() {
        PairingManager pm = new PairingManager(Duration.ofMinutes(10));
        assertThrows(IllegalArgumentException.class,
                () -> pm.issue("name with/slash"));
        assertThrows(IllegalArgumentException.class,
                () -> pm.issue("ok-name", "not-a-wg-key"));
    }

    @Test
    void auditTrailsIssueVerifyAndClaim() throws Exception {
        Path auditFile = tmp.resolve("audit.log");
        PairingManager pm = new PairingManager(Duration.ofMinutes(10), new AuditLog(auditFile));
        String token = pm.issue("john-laptop", KEY_JOHN);
        assertTrue(pm.verifyAndConsume(token, "john-laptop", "127.0.0.1"));
        pm.issue("desktop", KEY_OTHER);
        pm.claimForHandshake(KEY_OTHER);

        List<String> lines = Files.readAllLines(auditFile);
        String joined = String.join("\n", lines);
        assertTrue(joined.contains("token_issued"));
        assertTrue(joined.contains("token_verified"));
        assertTrue(joined.contains("token_consumed"));
        assertTrue(new AuditLog(auditFile).verifyChain());
    }
}