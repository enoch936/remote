package com.company.remoteaccess.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecretsRedactionTest {

    @Test
    void redactsPrivateKeyAssignments() {
        String in = "PrivateKey = 0123456789abcdef0123456789abcdef0123456789abcdef";
        String out = Secrets.redact(in);
        assertFalse(out.contains("0123456789abcdef"));
        assertTrue(out.contains("[REDACTED]"));
    }

    @Test
    void redactsLongBase64Keys() {
        StringBuilder sb = new StringBuilder("0123456789");
        for (int i = 0; i < 5; i++) {
            sb.append("abcdefghij");
        }
        String key = sb.toString(); // 50 chars
        String in = "peer key " + key + " in endpoint";
        String out = Secrets.redact(in);
        assertFalse(out.contains(key));
        assertTrue(out.contains("[REDACTED-KEY]"));
    }

    @Test
    void redactsLongHexStrings() {
        String hex = "a1b2c3d4e5f60718293a4b5c6d7e8f90011a2b3c4d5e6f708192a3b4c5d6e7f8";
        String out = Secrets.redact("token=" + hex);
        assertFalse(out.contains(hex));
    }

    @Test
    void doesNotMangleOrdinaryText() {
        String in = "connected to company-gateway at 10.50.0.1 port 51820";
        assertEquals(in, Secrets.redact(in));
    }

    @Test
    void nullAndEmptyArePassthrough() {
        assertEquals(null, Secrets.redact(null));
        assertEquals("", Secrets.redact(""));
    }

    @Test
    void constantEqualsIsConstantTimeCompatible() {
        assertTrue(Secrets.constantEquals("abc", "abc"));
        assertFalse(Secrets.constantEquals("abc", "abd"));
        assertFalse(Secrets.constantEquals("abcd", "abc"));
        assertFalse(Secrets.constantEquals(null, "abc"));
        assertTrue(Secrets.constantEquals(null, null));
    }

    @Test
    void tokensAreRandomAndSized() {
        String a = Secrets.randomToken();
        String b = Secrets.randomToken();
        assertNotEquals(a, b);
        assertEquals(43, a.length());
    }

    @Test
    void hashIsDeterministicSha256() {
        assertEquals(Secrets.hash256("same"), Secrets.hash256("same"));
        assertNotEquals(Secrets.hash256("a"), Secrets.hash256("b"));
        assertEquals(64, Secrets.hash256("x").length());
    }
}