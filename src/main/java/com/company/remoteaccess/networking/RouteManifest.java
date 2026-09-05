package com.company.remoteaccess.networking;

import com.company.remoteaccess.util.Json;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Persists the list of routes the application has added so they can be removed
 * on disconnect, shutdown, or after a previous crash.
 */
public final class RouteManifest {

    private final Path file;
    private final List<RouteEntry> routes = new ArrayList<>();

    public RouteManifest(Path file) {
        this.file = file;
    }

    public synchronized void load() {
        routes.clear();
        if (file == null || !Files.exists(file)) {
            return;
        }
        try {
            String json = Files.readString(file, StandardCharsets.UTF_8);
            var obj = Json.parseObject(json);
            var list = obj.getList("routes");
            if (list != null) {
                for (var r : list) {
                    routes.add(new RouteEntry(
                            r.get("network"),
                            Integer.parseInt(r.get("prefix")),
                            r.get("gateway"),
                            r.get("iface"),
                            Integer.parseInt(r.get("metric") == null ? "5" : r.get("metric")),
                            "true".equals(r.get("default")),
                            true));
                }
            }
        } catch (Exception e) {
            // corrupted manifest -> treat as empty
            throw new IllegalStateException("corrupted route manifest; manual cleanup may be required", e);
        }
    }

    public synchronized List<RouteEntry> all() {
        return List.copyOf(routes);
    }

    public synchronized void add(RouteEntry entry) {
        routes.add(entry);
        persist();
    }

    public synchronized void remove(RouteEntry entry) {
        routes.removeIf(r -> r.cidr().equals(entry.cidr())
                && java.util.Objects.equals(r.gateway(), entry.gateway()));
        persist();
    }

    public synchronized void clear() {
        routes.clear();
        persist();
    }

    private void persist() {
        if (file == null) {
            return;
        }
        try {
            Files.createDirectories(file.toAbsolutePath().getParent());
            StringBuilder sb = new StringBuilder("{\"routes\":[");
            boolean first = true;
            for (RouteEntry r : routes) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                sb.append("{\"network\":\"").append(r.network())
                        .append("\",\"prefix\":").append(r.prefix())
                        .append(",\"gateway\":\"").append(esc(r.gateway()))
                        .append("\",\"iface\":\"").append(esc(r.interfaceName()))
                        .append("\",\"metric\":").append(r.metric())
                        .append(",\"default\":").append(r.isDefault())
                        .append('}');
            }
            sb.append("]}");
            Files.writeString(file, sb.toString(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("cannot persist route manifest", e);
        }
    }

    private static String esc(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}