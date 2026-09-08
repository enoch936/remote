package com.company.remoteaccess.core.configuration;

import com.company.remoteaccess.core.state.Role;
import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.security.ConfigCipher;
import com.company.remoteaccess.security.ConfigIntegrity;
import com.company.remoteaccess.util.Yaml;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Map;

/**
 * Loads/saves the application configuration file. Non-secret settings only.
 * Writes are atomic (temp file + move) and previous versions are backed up.
 */
public final class ConfigManager {

    private final Path file;
    private final String integrityKey;
    private final String encryptionKey;

    public ConfigManager(Path file) {
        this(file, null, null);
    }

    /** @param integrityKey base64 HMAC key; {@code null} runs in legacy (unverified) mode. */
    public ConfigManager(Path file, String integrityKey) {
        this(file, integrityKey, null);
    }

    /**
     * @param integrityKey base64 HMAC key (legacy plaintext files); may be {@code null}.
     * @param encryptionKey base64 AES key for encryption at rest; {@code null} keeps
     *                      the plaintext format (used by tests and legacy deployments).
     */
    public ConfigManager(Path file, String integrityKey, String encryptionKey) {
        this.file = file;
        this.integrityKey = integrityKey;
        this.encryptionKey = encryptionKey;
    }

    public boolean exists() {
        return file != null && Files.exists(file);
    }

    /** Load configuration, returning a default when unconfigured. */
    public AppConfig load() {
        if (!exists()) {
            AppLogger.getLogger().info(LogCategory.SYSTEM, "no configuration found; using defaults");
            return AppConfig.create();
        }
        try {
            String text = Files.readString(file, StandardCharsets.UTF_8);
            text = decryptOrPassThrough(text);
            verifyIntegrity(text);
            Map<String, Object> data = Yaml.parse(text);
            int version = data.get("version") instanceof Number n
                    ? n.intValue()
                    : (data.get("version") == null ? 0 : Integer.parseInt(String.valueOf(data.get("version"))));
            if (version > AppConfig.CURRENT_VERSION) {
                throw new ConfigException(ConfigException.Kind.NEWER_VERSION,
                        "configuration was written by a newer application version; please upgrade");
            }
            AppConfig cfg = AppConfig.fromMap(data);
            var issues = ConfigValidator.validate(cfg);
            boolean fatal = issues.stream().anyMatch(i -> i.severity == ConfigValidator.Issue.Severity.ERROR);
            if (fatal) {
                StringBuilder msg = new StringBuilder("configuration is invalid:");
                issues.stream().filter(i -> i.severity == ConfigValidator.Issue.Severity.ERROR)
                        .forEach(i -> msg.append("\n - ").append(i.message));
                throw new ConfigException(ConfigException.Kind.INVALID, msg.toString());
            }
            return cfg;
        } catch (ConfigException e) {
            throw e;
        } catch (Exception e) {
            throw new ConfigException(ConfigException.Kind.PARSE_ERROR,
                    "configuration could not be parsed: " + e.getMessage(), e);
        }
    }

    public synchronized void save(AppConfig config) throws IOException {
        if (file == null) {
            throw new IOException("no configuration file path");
        }
        Files.createDirectories(file.toAbsolutePath().getParent());
        String yaml = Yaml.serialize(config.asMap());
        Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
        if (encryptionKey != null) {
            Files.writeString(tmp, ConfigCipher.encrypt(encryptionKey, yaml.getBytes(StandardCharsets.UTF_8)),
                    StandardCharsets.UTF_8);
        } else {
            Files.writeString(tmp, yaml, StandardCharsets.UTF_8);
        }
        if (Files.exists(file)) {
            Path backup = file.resolveSibling(file.getFileName() + ".bak");
            Files.move(file, backup, StandardCopyOption.REPLACE_EXISTING);
        }
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
        if (encryptionKey != null) {
            // GCM provides authenticity; the HMAC sidecar is superseded.
            Files.deleteIfExists(ConfigIntegrity.sidecarFor(file));
        } else {
            writeIntegrity(yaml);
        }
        AppLogger.getLogger().info(LogCategory.SYSTEM, "configuration saved (%s mode, %s)",
                config.mode() == Role.SERVER ? "server" : "client",
                encryptionKey != null ? "encrypted" : "plaintext");
    }

    /** Decrypt encrypted files; legacy plaintext passes through (checked by the sidecar). */
    private String decryptOrPassThrough(String text) {
        if (!ConfigCipher.isEncrypted(text)) {
            if (encryptionKey != null) {
                AppLogger.getLogger().info(LogCategory.SECURITY,
                        "legacy plaintext configuration loaded; next save encrypts it");
            }
            return text;
        }
        if (encryptionKey == null) {
            throw new ConfigException(ConfigException.Kind.STALE,
                    "configuration is encrypted but no decryption key is available");
        }
        try {
            return new String(ConfigCipher.decrypt(encryptionKey, text), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new ConfigException(ConfigException.Kind.STALE,
                    "configuration could not be decrypted (wrong key or modified file): "
                            + e.getMessage(), e);
        }
    }

    private void verifyIntegrity(String text) {
        if (integrityKey == null) {
            return;
        }
        Path mac = ConfigIntegrity.sidecarFor(file);
        if (!Files.exists(mac)) {
            AppLogger.getLogger().warn(LogCategory.SECURITY,
                    "configuration has no integrity sidecar; treating as legacy (unverified)");
            return;
        }
        String expected;
        try {
            expected = Files.readString(mac, StandardCharsets.UTF_8).trim();
        } catch (IOException e) {
            throw new ConfigException(ConfigException.Kind.STALE,
                    "configuration integrity sidecar could not be read: " + e.getMessage(), e);
        }
        String actual = ConfigIntegrity.hmac(integrityKey, text.getBytes(StandardCharsets.UTF_8));
        if (!ConfigIntegrity.constantEquals(expected, actual)) {
            AppLogger.getLogger().error(LogCategory.SECURITY,
                    "configuration integrity check FAILED; refusing to load");
            throw new ConfigException(ConfigException.Kind.STALE,
                    "configuration was modified since it was saved; restore " + file.getFileName()
                            + " from its backup or reset the configuration");
        }
    }

    private void writeIntegrity(String yaml) throws IOException {
        if (integrityKey == null) {
            return;
        }
        String mac = ConfigIntegrity.hmac(integrityKey, yaml.getBytes(StandardCharsets.UTF_8));
        Path macFile = ConfigIntegrity.sidecarFor(file);
        Path tmp = macFile.resolveSibling(macFile.getFileName() + ".tmp");
        Files.writeString(tmp, mac + System.lineSeparator(), StandardCharsets.UTF_8);
        Files.move(tmp, macFile, StandardCopyOption.REPLACE_EXISTING);
    }
}