package com.company.remoteaccess.vpn;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.platform.CommandResult;
import com.company.remoteaccess.platform.CommandRunner;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Generates WireGuard key pairs through the audited {code wg} tool. Never
 * implements cryptography itself and never prints private keys.
 */
public final class KeyManager {

    public record KeyPair(String privateKey, String publicKey) {
    }

    private final CommandRunner runner;
    private final String wgBinary;

    public KeyManager(CommandRunner runner, String wgBinary) {
        this.runner = runner;
        this.wgBinary = wgBinary;
    }

    public KeyPair generateKeyPair() throws VpnException {
        CommandResult gen = runner.run(wgBinary, "genkey");
        if (gen.failed() || gen.stdout() == null || gen.stdout().isBlank()) {
            throw new VpnException(VpnException.Kind.BINARIES_MISSING,
                    "Unable to invoke " + wgBinary + " genkey: " + gen.stderr());
        }
        String priv = gen.stdout().trim();
        String pub = derivePublicKey(priv);
        return new KeyPair(priv, pub);
    }

    public String derivePublicKey(String privateKey) throws VpnException {
        CommandResult pub = runner.runWithInput(
                List.of(wgBinary, "pubkey"), privateKey + "\n", 30);
        if (pub.failed() || pub.stdout() == null || pub.stdout().isBlank()) {
            throw new VpnException(VpnException.Kind.BINARIES_MISSING,
                    "Unable to derive public key: " + pub.stderr());
        }
        return pub.stdout().trim();
    }

    /**
     * Locate the {@code wg} binary. Look-up order: configured directory, PATH,
     * then well-known install locations per-platform.
     */
    public static Optional<String> findWgBinary(CommandRunner runner, String configuredDir) {
        List<String> candidates = new ArrayList<>();
        if (configuredDir != null && !configuredDir.isBlank()) {
            candidates.add(configuredDir + java.io.File.separator + "wg" + exe());
        }
        if (System.getenv("WIREGUARD_HOME") != null
                && !System.getenv("WIREGUARD_HOME").isBlank()) {
            candidates.add(System.getenv("WIREGUARD_HOME") + java.io.File.separator
                    + "wg" + exe());
        }
        if (com.company.remoteaccess.platform.Os.isWindows()) {
            String pf = System.getenv("ProgramFiles");
            candidates.add((pf == null ? "C:\\Program Files" : pf)
                    + "\\WireGuard\\wg.exe");
        } else {
            candidates.add("/usr/bin/wg");
            candidates.add("/usr/local/bin/wg");
        }
        for (String c : candidates) {
            if (Files.isExecutable(Path.of(c))) {
                return Optional.of(c);
            }
        }
        // last resort: PATH
        String which = com.company.remoteaccess.platform.Os.isWindows() ? "where.exe" : "which";
        CommandResult r = runner.run(which, "wg");
        if (r.success() && r.stdout() != null && !r.stdout().isBlank()) {
            return Optional.of(r.stdout().lines().findFirst().orElse("").trim());
        }
        return Optional.empty();
    }

    public String binary() {
        return wgBinary;
    }

    private static String exe() {
        return com.company.remoteaccess.platform.Os.isWindows() ? ".exe" : "";
    }
}