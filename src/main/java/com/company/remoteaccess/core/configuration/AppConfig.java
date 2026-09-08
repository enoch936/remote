package com.company.remoteaccess.core.configuration;

import com.company.remoteaccess.core.state.Role;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Typed, immutable view over the (mostly) YAML configuration document.
 * Secret material (private keys, pairing tokens) is never stored here; it lives
 * in the {@link com.company.remoteaccess.security.CredentialStore}.
 */
public final class AppConfig {

    public static final int CURRENT_VERSION = 1;

    private final int version;
    private final Role mode;
    private final Map<String, Object> data;

    private AppConfig(int version, Role mode, Map<String, Object> data) {
        this.version = version;
        this.mode = mode;
        this.data = data;
    }

    public static AppConfig create() {
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("version", CURRENT_VERSION);
        config.put("mode", "CLIENT");
        config.put("name", "My Computer");

        Map<String, Object> server = new LinkedHashMap<>();
        server.put("name", "Company-Gateway");
        server.put("host", "");
        server.put("listenPort", 51820);
        server.put("lan", "");
        server.put("lanInterface", "");
        server.put("vpnSubnet", "10.50.0.0/24");
        server.put("mtu", 1420);
        server.put("persistentKeepalive", 25);
        config.put("server", server);

        Map<String, Object> vpn = new LinkedHashMap<>();
        vpn.put("provider", "wireguard");
        vpn.put("tunnelName", "company0");
        vpn.put("binaryDir", "");
        config.put("vpn", vpn);

        Map<String, Object> network = new LinkedHashMap<>();
        network.put("detectIntervalMs", 3000);
        config.put("network", network);

        Map<String, Object> routing = new LinkedHashMap<>();
        routing.put("mode", "SPLIT_TUNNEL");
        routing.put("routes", new ArrayList<String>());
        config.put("routing", routing);

        Map<String, Object> security = new LinkedHashMap<>();
        security.put("autoReconnect", true);
        security.put("maxRetries", 5);
        security.put("backoffBaseMs", 2000);
        security.put("connectOnAppStart", false);
        config.put("security", security);

        Map<String, Object> client = new LinkedHashMap<>();
        client.put("deviceName", "");
        client.put("serverEndpoint", "");
        client.put("dnsOverride", "");
        client.put("vpnIp", "");
        client.put("pairApplied", false);
        client.put("pubKeyHash", "");
        config.put("client", client);

        Map<String, Object> startup = new LinkedHashMap<>();
        startup.put("startWithOS", false);
        config.put("startup", startup);

        Map<String, Object> app = new LinkedHashMap<>();
        app.put("theme", "dark");
        app.put("setupDone", false);
        config.put("app", app);

        return new AppConfig(CURRENT_VERSION, Role.CLIENT, config);
    }

    public static AppConfig fromMap(Map<String, Object> data) {
        int version = intVal(data.get("version"), CURRENT_VERSION);
        Role mode = Role.fromString(strVal(data.get("mode"), "CLIENT"));
        return new AppConfig(version, mode, new LinkedHashMap<>(data));
    }

    public int version() {
        return version;
    }

    public Role mode() {
        return mode;
    }

    public Map<String, Object> asMap() {
        return deepCopy(data);
    }

    public String name() {
        return strVal(data.get("name"), "");
    }

    public String theme() {
        var app = section(data, "app");
        return strVal(app.get("theme"), "dark");
    }

    /** Whether the first-run role/setup wizard has completed. */
    public boolean setupDone() {
        return boolVal(section(data, "app").get("setupDone"), false);
    }

    /**
     * Decide whether setup is complete. The wizard must run once (recorded via the
     * {@code app.setupDone} marker). Seat configs written before that marker existed
     * are only honored when they are genuinely ready — a paired client (marker absent)
     * or a gateway that generated its server keys — otherwise the first-run role
     * chooser re-opens instead of silently defaulting to a role.
     */
    public static boolean isSetupComplete(AppConfig cfg, boolean clientReady, boolean serverKeyPresent) {
        if (cfg == null) {
            return false;
        }
        if (cfg.setupDone()) {
            return true;
        }
        return cfg.mode() == Role.CLIENT ? clientReady : serverKeyPresent;
    }

    // ----- server section -----

    public String serverName() {
        return strVal(section(data, "server").get("name"), "Company-Gateway");
    }

    public String serverHost() {
        return strVal(section(data, "server").get("host"), "");
    }

    public int listenPort() {
        return intVal(section(data, "server").get("listenPort"), 51820);
    }

    public String lanInterface() {
        return strVal(section(data, "server").get("lanInterface"), "");
    }

    public String lanCidr() {
        return strVal(section(data, "server").get("lan"), "");
    }

    public String vpnSubnet() {
        return strVal(section(data, "server").get("vpnSubnet"), "10.50.0.0/24");
    }

    public int mtu() {
        return intVal(section(data, "server").get("mtu"), 1420);
    }

    public int persistentKeepalive() {
        return intVal(section(data, "server").get("persistentKeepalive"), 25);
    }

    // ----- vpn section -----

    public String vpnProvider() {
        return strVal(section(data, "vpn").get("provider"), "wireguard");
    }

    public String tunnelName() {
        return strVal(section(data, "vpn").get("tunnelName"), "company0");
    }

    public String wgBinaryDir() {
        return strVal(section(data, "vpn").get("binaryDir"), "");
    }

    // ----- routing section -----

    public String routingMode() {
        return strVal(section(data, "routing").get("mode"), "SPLIT_TUNNEL");
    }

    @SuppressWarnings("unchecked")
    public List<String> extraRoutes() {
        Object v = section(data, "routing").get("routes");
        if (v instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        return List.of();
    }

    // ----- security section -----

    public boolean autoReconnect() {
        return boolVal(section(data, "security").get("autoReconnect"), true);
    }

    public int maxRetries() {
        return intVal(section(data, "security").get("maxRetries"), 5);
    }

    public int backoffBaseMs() {
        return intVal(section(data, "security").get("backoffBaseMs"), 2000);
    }

    public boolean connectOnAppStart() {
        return boolVal(section(data, "security").get("connectOnAppStart"), false);
    }

    // ----- client section -----

    public String clientDeviceName() {
        return strVal(section(data, "client").get("deviceName"), "");
    }

    public String clientVpnIp() {
        return strVal(section(data, "client").get("vpnIp"), "");
    }

    public String clientServerEndpoint() {
        return strVal(section(data, "client").get("serverEndpoint"), "");
    }

    public String clientDnsOverride() {
        return strVal(section(data, "client").get("dnsOverride"), "");
    }

    public boolean clientPairApplied() {
        return boolVal(section(data, "client").get("pairApplied"), false);
    }

    /** SHA-256 pin of this device's WireGuard public key, recorded at pairing. Empty when not pinned. */
    public String clientPubKeyHash() {
        return strVal(section(data, "client").get("pubKeyHash"), "");
    }

    // ----- startup section -----

    public boolean startWithOS() {
        return boolVal(section(data, "startup").get("startWithOS"), false);
    }

    // ----- editing -----

    public AppConfig with(String path, Object value) {
        Map<String, Object> copy = deepCopy(data);
        String[] keys = path.split("\\.");
        Map<String, Object> node = copy;
        for (int i = 0; i < keys.length - 1; i++) {
            node = (Map<String, Object>) node.computeIfAbsent(keys[i], k -> new LinkedHashMap<>());
        }
        node.put(keys[keys.length - 1], value);
        return AppConfig.fromMap(copy);
    }

    @SuppressWarnings("unchecked")
    public AppConfig withSection(String section, Map<String, Object> values) {
        Map<String, Object> copy = deepCopy(data);
        Map<String, Object> sectionMap = (Map<String, Object>) copy.computeIfAbsent(section,
                k -> new LinkedHashMap<>());
        sectionMap.putAll(values);
        return AppConfig.fromMap(copy);
    }

    // ----- helpers -----

    public Object get(String path) {
        String[] keys = path.split("\\.");
        Object node = data;
        for (String k : keys) {
            if (!(node instanceof Map<?, ?> m)) {
                return null;
            }
            node = ((Map<?, ?>) m).get(k);
        }
        return node;
    }

    private static Map<String, Object> section(Map<String, Object> root, String key) {
        Object v = root.get(key);
        if (!(v instanceof Map<?, ?> m)) {
            return Map.of();
        }
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : m.entrySet()) {
            out.put(String.valueOf(e.getKey()), e.getValue());
        }
        return out;
    }

    private static String strVal(Object v, String dflt) {
        return v == null ? dflt : String.valueOf(v);
    }

    private static int intVal(Object v, int dflt) {
        if (v instanceof Number n) {
            return n.intValue();
        }
        if (v instanceof String s) {
            try {
                return Integer.parseInt(s.trim());
            } catch (NumberFormatException ignored) {
                return dflt;
            }
        }
        return dflt;
    }

    private static boolean boolVal(Object v, boolean dflt) {
        if (v == null) {
            return dflt;
        }
        if (v instanceof Boolean b) {
            return b;
        }
        return String.valueOf(v).equalsIgnoreCase("true");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> deepCopy(Map<String, Object> src) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : src.entrySet()) {
            Object v = e.getValue();
            if (v instanceof Map<?, ?> m) {
                Map<String, Object> m2 = new LinkedHashMap<>();
                for (Map.Entry<?, ?> me : m.entrySet()) {
                    m2.put(String.valueOf(me.getKey()), me.getValue());
                }
                out.put(e.getKey(), deepCopy(m2));
            } else if (v instanceof List<?> list) {
                out.put(e.getKey(), new ArrayList<>(list));
            } else {
                out.put(e.getKey(), v);
            }
        }
        return out;
    }
}