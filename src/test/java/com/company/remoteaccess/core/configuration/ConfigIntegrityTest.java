package com.company.remoteaccess.core.configuration;

import com.company.remoteaccess.security.ConfigIntegrity;
import com.company.remoteaccess.security.CredentialStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigIntegrityTest {

    @TempDir
    Path tmp;

    private CredentialStore store() throws IOException {
        CredentialStore store = new CredentialStore(tmp.resolve("secrets"));
        store.initialize();
        return store;
    }

    @Test
    void saveWithIntegrityKeyWritesSidecarAndLoadsClean() throws Exception {
        CredentialStore store = store();
        String key = ConfigIntegrity.keyFor(store);
        Path file = tmp.resolve("config.yaml");
        ConfigManager manager = new ConfigManager(file, key);
        manager.save(serverCfg("HQ"));

        assertTrue(Files.exists(ConfigIntegrity.sidecarFor(file)));

        ConfigManager reader = new ConfigManager(file, key);
        assertEquals("HQ", reader.load().serverName());
    }

    @Test
    void tamperedConfigThrowsStale() throws Exception {
        CredentialStore store = store();
        String key = ConfigIntegrity.keyFor(store);
        Path file = tmp.resolve("config.yaml");
        new ConfigManager(file, key).save(serverCfg("HQ"));

        String content = Files.readString(file, StandardCharsets.UTF_8)
                .replace("HQ", "INTRUDER");
        Files.writeString(file, content, StandardCharsets.UTF_8);

        ConfigManager reader = new ConfigManager(file, key);
        ConfigException e = assertThrows(ConfigException.class, reader::load);
        assertEquals(ConfigException.Kind.STALE, e.kind());
    }

    @Test
    void sidecarTamperThrowsStale() throws Exception {
        CredentialStore store = store();
        String key = ConfigIntegrity.keyFor(store);
        Path file = tmp.resolve("config.yaml");
        new ConfigManager(file, key).save(serverCfg("HQ"));

        Files.writeString(ConfigIntegrity.sidecarFor(file), "0".repeat(64), StandardCharsets.UTF_8);

        ConfigManager reader = new ConfigManager(file, key);
        assertThrows(ConfigException.class, reader::load);
    }

    @Test
    void missingSidecarIsAcceptedAsLegacy() throws Exception {
        CredentialStore store = store();
        String key = ConfigIntegrity.keyFor(store);
        Path file = tmp.resolve("config.yaml");
        new ConfigManager(file).save(serverCfg("Old"));

        ConfigManager reader = new ConfigManager(file, key);
        assertEquals("Old", reader.load().serverName());
    }

    @Test
    void rewrittenAfterTamperRepairsIntegrity() throws Exception {
        CredentialStore store = store();
        String key = ConfigIntegrity.keyFor(store);
        Path file = tmp.resolve("config.yaml");
        ConfigManager manager = new ConfigManager(file, key);
        manager.save(serverCfg("HQ"));
        Files.writeString(file,
                Files.readString(file, StandardCharsets.UTF_8).replace("HQ", "X"),
                StandardCharsets.UTF_8);
        assertThrows(ConfigException.class, new ConfigManager(file, key)::load);

        manager.save(serverCfg("HQ2"));
        assertEquals("HQ2", new ConfigManager(file, key).load().serverName());
    }

    @Test
    void keyWithoutIntegrityManagerDoesNotVerify() throws Exception {
        CredentialStore store = store();
        String key = ConfigIntegrity.keyFor(store);
        Path file = tmp.resolve("config.yaml");
        new ConfigManager(file, key).save(serverCfg("HQ"));
        Files.writeString(file,
                Files.readString(file, StandardCharsets.UTF_8).replace("HQ", "X"),
                StandardCharsets.UTF_8);

        // legacy manager ignores the sidecar entirely
        assertEquals("X", new ConfigManager(file).load().serverName());
    }

    private static AppConfig serverCfg(String name) {
        return AppConfig.create().with("mode", "SERVER").with("server.name", name);
    }

    @Test
    void keyForIsStableAcrossInstances() throws Exception {
        CredentialStore store = store();
        String first = ConfigIntegrity.keyFor(store);
        String second = ConfigIntegrity.keyFor(store);
        assertEquals(first, second);
        assertTrue(store.has(ConfigIntegrity.KEY_CRED));
    }

    @Test
    void hmacIsDeterministicAndKeyed() {
        byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
        String k1 = "c2VjcmV0LWtleS1vbmU=";
        String k2 = "c2VjcmV0LWtleS10d28=";
        assertEquals(ConfigIntegrity.hmac(k1, data), ConfigIntegrity.hmac(k1, data));
        assertNotEquals(ConfigIntegrity.hmac(k1, data), ConfigIntegrity.hmac(k2, data));
        assertEquals(64, ConfigIntegrity.hmac(k1, data).length());
    }
}