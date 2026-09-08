package com.company.remoteaccess.security;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;

/**
 * Encryption at rest for the configuration file.
 *
 * <p>When enabled, {@code config.yaml} is AES-256-GCM encrypted with a 96-bit
 * random nonce. The key lives in the OS-restricted credential store, the
 * authenticating tag provides tamper evidence, and a versioned header keeps the
 * format forward-readable. Legacy (plaintext) configurations are still loadable,
 * and the first save migrates them to the encrypted format.
 *
 * <p>Honest limits: the key file is protected by the same user ACLs as the rest
 * of the credential store, so this protects the configuration content from
 * casual reads and tampering, not against a fully compromised user account.
 */
public final class ConfigCipher {

    public static final String KEY_CRED = "config-encryption-key";
    private static final String HEADER = "cra-enc:v1:";
    private static final int KEY_BYTES = 32;
    private static final int IV_BYTES = 12;

    private ConfigCipher() {
    }

    /** Load or create the config-encryption secret (32 random bytes, base64). */
    public static String keyFor(CredentialStore store) throws IOException {
        Optional<String> existing = store.get(KEY_CRED);
        if (existing.isPresent()) {
            return existing.get();
        }
        String key = Base64.getEncoder().withoutPadding()
                .encodeToString(Secrets.randomBytes(KEY_BYTES));
        store.put(KEY_CRED, key);
        AppLogger.getLogger().info(LogCategory.SECURITY,
                "configuration encryption key created");
        return key;
    }

    /** True when {@code text} already uses the encryption-at-rest format. */
    public static boolean isEncrypted(String text) {
        return text != null && text.startsWith(HEADER);
    }

    /** AES-256-GCM encrypt; returns {@code cra-enc:v1:} + base64(iv || ciphertext+tag). */
    public static String encrypt(String keyB64, byte[] plaintext) {
        try {
            byte[] key = Base64.getDecoder().decode(keyB64);
            byte[] iv = new byte[IV_BYTES];
            new SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, iv));
            byte[] sealed = cipher.doFinal(plaintext);
            byte[] out = new byte[iv.length + sealed.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(sealed, 0, out, iv.length, sealed.length);
            return HEADER + Base64.getEncoder().encodeToString(out);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("configuration encryption key is corrupt", e);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM unavailable: " + e.getMessage(), e);
        }
    }

    /** Decrypt a {@link #encrypt} payload; rejects wrong keys and tampered data. */
    public static byte[] decrypt(String keyB64, String token) throws IOException {
        if (token == null || !token.startsWith(HEADER)) {
            throw new IOException("configuration is not in encrypted format");
        }
        byte[] payload;
        try {
            payload = Base64.getDecoder().decode(token.substring(HEADER.length()));
        } catch (IllegalArgumentException e) {
            throw new IOException("encrypted configuration payload is malformed", e);
        }
        if (payload.length < IV_BYTES) {
            throw new IOException("encrypted configuration payload is truncated");
        }
        byte[] key = Base64.getDecoder().decode(keyB64);
        byte[] iv = new byte[IV_BYTES];
        System.arraycopy(payload, 0, iv, 0, IV_BYTES);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, iv));
            return cipher.doFinal(payload, IV_BYTES, payload.length - IV_BYTES);
        } catch (Exception e) {
            throw new IOException("configuration could not be decrypted "
                    + "(wrong key or modified file)", e);
        }
    }
}