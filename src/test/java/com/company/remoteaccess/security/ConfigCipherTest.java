package com.company.remoteaccess.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigCipherTest {

    @TempDir
    Path tmp;

    private CredentialStore store() throws IOException {
        CredentialStore store = new CredentialStore(tmp.resolve("secrets"));
        store.initialize();
        return store;
    }

    @Test
    void roundTrip() throws Exception {
        String key = ConfigCipher.keyFor(store());
        byte[] payload = "mode: CLIENT".getBytes(StandardCharsets.UTF_8);
        String token = ConfigCipher.encrypt(key, payload);
        assertTrue(ConfigCipher.isEncrypted(token));
        assertEquals("mode: CLIENT", new String(ConfigCipher.decrypt(key, token), StandardCharsets.UTF_8));
    }

    @Test
    void encryptedBlobIsNotPlaintextReadable() throws Exception {
        String key = ConfigCipher.keyFor(store());
        String token = ConfigCipher.encrypt(key, "server.name: HQ".getBytes(StandardCharsets.UTF_8));
        assertFalse(token.contains("HQ"));
        assertNotEquals(token, "server.name: HQ");
    }

    @Test
    void tamperIsRejected() throws Exception {
        String key = ConfigCipher.keyFor(store());
        String token = ConfigCipher.encrypt(key, "secret: abc".getBytes(StandardCharsets.UTF_8));
        String tampered = token.substring(0, token.length() - 4)
                + (token.endsWith("AAAA") ? "BBBB" : "AAAA");
        assertThrows(IOException.class, () -> ConfigCipher.decrypt(key, tampered));
    }

    @Test
    void wrongKeyIsRejected() throws Exception {
        CredentialStore s = store();
        String keyA = ConfigCipher.keyFor(s);
        String token = ConfigCipher.encrypt(keyA, "data: x".getBytes(StandardCharsets.UTF_8));
        CredentialStore other = new CredentialStore(tmp.resolve("secrets2"));
        other.initialize();
        String keyB = ConfigCipher.keyFor(other);
        assertThrows(IOException.class, () -> ConfigCipher.decrypt(keyB, token));
    }

    @Test
    void nonEncryptedInputIsRejected() throws Exception {
        assertThrows(IOException.class,
                () -> ConfigCipher.decrypt(ConfigCipher.keyFor(store()), "plain config"));
    }

    @Test
    void keyIsStableAcrossInstances() throws Exception {
        CredentialStore s = store();
        assertEquals(ConfigCipher.keyFor(s), ConfigCipher.keyFor(s));
        assertTrue(s.has(ConfigCipher.KEY_CRED));
    }
}