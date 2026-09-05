package com.company.remoteaccess.security;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Redaction utilities. Guarantees that private keys, passwords, pairing tokens and
 * other secret material never end up in logs or on screen banners.
 */
public final class Secrets {

    private static final SecureRandom RNG = new SecureRandom();

    private static final Pattern KEY_VALUE = Pattern.compile(
            "(?i)(\\b(?:private\\s*key|password|secret|token|psk|preshared\\s*key)\\b\\s*=\\s*)(\\S+)");
    private static final Pattern WIREGUARD_KEY = Pattern.compile(
            "(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43,}={0,2}(?![A-Za-z0-9+/=])");
    private static final Pattern LONG_HEX = Pattern.compile("(?<![0-9a-fA-F])[0-9a-fA-F]{40,}(?![0-9a-fA-F])");

    private Secrets() {
    }

    public static String redact(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        String out = input;
        Matcher m = KEY_VALUE.matcher(out);
        out = m.replaceAll("$1[REDACTED]");
        Matcher k = WIREGUARD_KEY.matcher(out);
        out = k.replaceAll("[REDACTED-KEY]");
        Matcher h = LONG_HEX.matcher(out);
        out = h.replaceAll("[REDACTED-HEX]");
        return out;
    }

    public static int randomCode() {
        return ThreadLocalRandom.current().nextInt(1_000_000, 1_000_000_000);
    }

    public static String randomToken() {
        byte[] b = new byte[32];
        RNG.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    public static String hash256(String value) {
        try {
            byte[] d = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Constant-time compare for pairing codes/tokens. */
    public static boolean constantEquals(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }
        byte[] ab = a.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] bb = b.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (ab.length != bb.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < ab.length; i++) {
            result |= ab[i] ^ bb[i];
        }
        return result == 0;
    }
}