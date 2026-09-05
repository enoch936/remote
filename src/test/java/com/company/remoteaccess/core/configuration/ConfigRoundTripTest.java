package com.company.remoteaccess.core.configuration;

import com.company.remoteaccess.core.state.Role;
import com.company.remoteaccess.util.Yaml;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigRoundTripTest {

    @TempDir
    Path tmp;

    @Test
    void defaultsAreSane() {
        AppConfig cfg = AppConfig.create();
        assertEquals(1, cfg.version());
        assertEquals(Role.CLIENT, cfg.mode());
        assertEquals("company0", cfg.tunnelName());
        assertEquals("10.50.0.0/24", cfg.vpnSubnet());
        assertEquals(51820, cfg.listenPort());
        assertEquals("SPLIT_TUNNEL", cfg.routingMode());
    }

    @Test
    void yamlRoundTripPreservesValues() {
        AppConfig cfg = AppConfig.create()
                .with("mode", "SERVER")
                .with("server.lan", "192.168.1.0/24")
                .with("routing.mode", "FULL_TUNNEL")
                .with("security.autoReconnect", false)
                .with("client.vpnIp", "10.50.0.4")
                .with("routing.routes", java.util.List.of("172.16.0.0/12"));
        String yaml = Yaml.serialize(cfg.asMap());
        Map<String, Object> parsed = Yaml.parse(yaml);
        AppConfig reloaded = AppConfig.fromMap(parsed);

        assertEquals(Role.SERVER, reloaded.mode());
        assertEquals("192.168.1.0/24", reloaded.lanCidr());
        assertEquals("FULL_TUNNEL", reloaded.routingMode());
        assertEquals(false, reloaded.autoReconnect());
        assertEquals("10.50.0.4", reloaded.clientVpnIp());
        assertEquals(1, reloaded.extraRoutes().size());
        assertEquals("172.16.0.0/12", reloaded.extraRoutes().get(0));
    }

    @Test
    void saveLoadRoundTrip() throws IOException {
        ConfigManager manager = new ConfigManager(tmp.resolve("config.yaml"));
        AppConfig cfg = AppConfig.create()
                .with("mode", "CLIENT")
                .with("client.serverEndpoint", "gw.example.com:51820");
        manager.save(cfg);

        ConfigManager other = new ConfigManager(tmp.resolve("config.yaml"));
        AppConfig loaded = other.load();
        assertEquals("gw.example.com:51820", loaded.clientServerEndpoint());
        assertEquals(Role.CLIENT, loaded.mode());
        assertTrue(other.exists());
    }

    @Test
    void withPathFallsBackToSectionGet() {
        AppConfig cfg = AppConfig.create();
        assertEquals("dark", cfg.theme());
        AppConfig light = cfg.with("app.theme", "light");
        assertEquals("light", light.theme());
        // original untouched (immutability)
        assertEquals("dark", cfg.theme());
    }
}