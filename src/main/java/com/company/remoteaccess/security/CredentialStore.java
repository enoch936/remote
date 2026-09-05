package com.company.remoteaccess.security;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.platform.CommandResult;
import com.company.remoteaccess.platform.CommandRunner;
import com.company.remoteaccess.platform.FilePermissions;
import com.company.remoteaccess.platform.Os;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Optional;

/**
 * OS-backed credential storage.
 *
 * <p>Private keys and pairing secrets are stored in a user-profile directory
 * protected by the operating system's ACLs (Windows {@code icacls} restricted to
 * the current user; POSIX mode 0600). There are no secrets in plain config files.
 */
public final class CredentialStore {

    private final Path baseDir;

    public CredentialStore(Path baseDir) {
        this.baseDir = baseDir;
    }

    public void initialize() throws IOException {
        Files.createDirectories(baseDir);
        FilePermissions.hardenDirectory(baseDir);
        AppLogger.getLogger().info(LogCategory.SECURITY, "credential store initialized at %s",
                baseDir.getFileName() == null ? baseDir : "store");
    }

    private Path fileFor(String name) {
        String safe = name.replaceAll("[^A-Za-z0-9._-]", "_");
        return baseDir.resolve(safe + ".secret");
    }

    public void put(String name, String secret) throws IOException {
        Path f = fileFor(name);
        boolean wasCreated = !Files.exists(f);
        Files.writeString(f, secret, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);
        FilePermissions.hardenFile(f);
        if (wasCreated) {
            AppLogger.getLogger().info(LogCategory.SECURITY, "credential stored: %s", name);
        }
    }

    public Optional<String> get(String name) throws IOException {
        Path f = fileFor(name);
        if (!Files.exists(f)) {
            return Optional.empty();
        }
        return Optional.of(Files.readString(f, StandardCharsets.UTF_8).trim());
    }

    public void delete(String name) throws IOException {
        Files.deleteIfExists(fileFor(name));
    }

    public List<String> list() throws IOException {
        try (var s = Files.list(baseDir)) {
            return s.filter(p -> p.getFileName().toString().endsWith(".secret"))
                    .map(p -> p.getFileName().toString().replace(".secret", ""))
                    .sorted()
                    .toList();
        }
    }

    public boolean has(String name) throws IOException {
        return Files.exists(fileFor(name));
    }
}