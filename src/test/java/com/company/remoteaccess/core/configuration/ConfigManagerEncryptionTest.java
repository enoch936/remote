package com.company.remoteaccess.core.configuration;

import com.company.remoteaccess.security.ConfigCipher;
import com.company.remoteaccess.security.ConfigIntegrity;
import com.company.remoteaccess.security.CredentialStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigManagerEncryptionTest {

    @TempDir
    Path tmp;

    private CredentialStore store() throws IOException {
        CredentialStore store = new CredentialStore(tmp.resolve("secrets"));
        store.initialize();
        return store;
    }

    private ConfigManager encryptedManager(Path file) throws IOException {
        CredentialStore store = store();
        return new ConfigManager(file, ConfigIntegrity.keyFor(store), ConfigCipher.keyFor(store));
    }

    @Test
    void saveEncryptsFileAndLoadsCleanly() throws Exception {
        Path file = tmp.resolve("config.yaml");
        ConfigManager manager = encryptedManager(file);
        manager.save(serverCfg("HQ"));

        String onDisk = Files.readString(file, StandardCharsets.UTF_8);
        assertTrue(ConfigCipher.isEncrypted(onDisk));
        assertFalse(onDisk.contains("HQ"));
        assertFalse(Files.exists(ConfigIntegrity.sidecarFor(file)));

        assertEquals("HQ", encryptedManager(file).load().serverName());
    }

    @Test
    void legacyPlaintextIsLoadedThenUpgradedOnSave() throws Exception {
        Path file = tmp.resolve("config.yaml");
        new ConfigManager(file).save(serverCfg("Legacy"));
        assertFalse(ConfigCipher.isEncrypted(Files.readString(file, StandardCharsets.UTF_8)));

        ConfigManager upgraded = encryptedManager(file);
        assertEquals("Legacy", upgraded.load().serverName());
        upgraded.save(serverCfg("Legacy-v2"));

        String onDisk = Files.readString(file, StandardCharsets.UTF_8);
        assertTrue(ConfigCipher.isEncrypted(onDisk));
        assertFalse(onDisk.contains("Legacy-v2"));
    }

    @Test
    void tamperedEncryptedConfigIsRejectedAsStale() throws Exception {
        Path file = tmp.resolve("config.yaml");
        ConfigManager manager = encryptedManager(file);
        manager.save(serverCfg("HQ"));

        String onDisk = Files.readString(file, StandardCharsets.UTF_8);
        Files.writeString(file, onDisk.substring(0, onDisk.length() - 3) + "===", StandardCharsets.UTF_8);

        ConfigException e = assertThrows(ConfigException.class, () -> encryptedManager(file).load());
        assertEquals(ConfigException.Kind.STALE, e.kind());
    }

    @Test
    void wrongKeyIsRejectedAsStale() throws Exception {
        Path file = tmp.resolve("config.yaml");
        CredentialStore s = store();
        ConfigManager manager = new ConfigManager(file,
                ConfigIntegrity.keyFor(s), ConfigCipher.keyFor(s));
        manager.save(serverCfg("HQ"));

        CredentialStore other = new CredentialStore(tmp.resolve("secrets-other"));
        other.initialize();
        ConfigManager wrong = new ConfigManager(file,
                ConfigIntegrity.keyFor(other), ConfigCipher.keyFor(other));
        ConfigException e = assertThrows(ConfigException.class, wrong::load);
        assertEquals(ConfigException.Kind.STALE, e.kind());
    }

    @Test
    void encryptedFileWithoutKeyIsRejectedAsStale() throws Exception {
        Path file = tmp.resolve("config.yaml");
        encryptedManager(file).save(serverCfg("HQ"));

        ConfigException e = assertThrows(ConfigException.class,
                () -> new ConfigManager(file, null, null).load());
        assertEquals(ConfigException.Kind.STALE, e.kind());
    }

    private static AppConfig serverCfg(String name) {
        return AppConfig.create().with("mode", "SERVER").with("server.name", name);
    }
}