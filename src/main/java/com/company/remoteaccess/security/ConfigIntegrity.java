package com.company.remoteaccess.security;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Optional;

/**
 * Tamper-evident configuration support.
 *
 * <p>The configuration file itself stays readable (it holds no secrets) but a
 * sidecar holding a keyed HMAC-SHA256 of the exact file bytes is written next to
 * it. The HMAC key lives in the OS-restricted credential store, so accidental
 * edits or low-skill tampering of {@code config.yaml} - without touching the
 * user-restricted secrets - is detected on load.
 *
 * <p>Honest limits: a same-user attacker who can write the data directory can
 * also delete/re-create the sidecar or the key file. This protects against
 * corruption and casual tampering, not against a fully compromised account.
 */
public final class ConfigIntegrity {

    public static final String KEY_CRED = "config-integrity-key";

    private ConfigIntegrity() {
    }

    /** Location of the HMAC sidecar next to a configuration file. */
    public static Path sidecarFor(Path configFile) {
        return configFile.resolveSibling(configFile.getFileName() + ".mac");
    }

    /** Load or create the keyed-control secret. Base64, 32 random bytes. */
    public static String keyFor(CredentialStore store) throws IOException {
        Optional<String> existing = store.get(KEY_CRED);
        if (existing.isPresent()) {
            return existing.get();
        }
        String key = Base64.getEncoder().withoutPadding()
                .encodeToString(Secrets.randomBytes(32));
        store.put(KEY_CRED, key);
        AppLogger.getLogger().info(LogCategory.SECURITY,
                "configuration integrity key created");
        return key;
    }

    /** Hex HMAC-SHA256 of the exact configuration bytes. */
    public static String hmac(String keyB64, byte[] data) {
        try {
            byte[] key = Base64.getDecoder().decode(keyB64);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return hex(mac.doFinal(data));
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("configuration integrity key is corrupt", e);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable: " + e.getMessage(), e);
        }
    }

    /** Constant-time comparison of two hex HMACs. */
    public static boolean constantEquals(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }

    private static String hex(byte[] digest) {
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}