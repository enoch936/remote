package com.company.remoteaccess.server;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.util.Json;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Persistent, JSON-backed registry of authorized devices. Changes are written
 * atomically; {@link ServerPeer} entries reference device public keys only —
 * never private keys.
 */
public final class ClientRegistry {

    public interface Listener {
        void onDevicesChanged(List<ServerPeer> devices);
    }

    private final Path file;
    private final CopyOnWriteArrayList<ServerPeer> devices = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<Listener> listeners = new CopyOnWriteArrayList<>();

    public ClientRegistry(Path file) {
        this.file = file;
        load();
    }

    public void addListener(Listener listener) {
        listeners.add(listener);
    }

    public synchronized void load() {
        devices.clear();
        if (file == null || !Files.exists(file)) {
            return;
        }
        try {
            String json = Files.readString(file, StandardCharsets.UTF_8);
            var obj = Json.parseObject(json);
            var list = obj.getList("devices");
            if (list != null) {
                for (var d : list) {
                    devices.add(new ServerPeer(
                            d.get("deviceName"),
                            d.get("publicKey"),
                            d.get("vpnAddress"),
                            ServerPeer.Status.valueOf(d.get("status") == null
                                    ? "AUTHORIZED" : d.get("status")),
                            d.get("addedAt"),
                            d.get("lastSeenAt"),
                            d.get("note")));
                }
            }
            AppLogger.getLogger().info(LogCategory.SERVER,
                    "client registry loaded: %d authorized device(s)", countAuthorized());
        } catch (Exception e) {
            AppLogger.getLogger().error(LogCategory.SERVER, e, "client registry read failed");
        }
    }

    public List<ServerPeer> all() {
        return List.copyOf(devices);
    }

    public List<ServerPeer> authorized() {
        return devices.stream()
                .filter(d -> d.status == ServerPeer.Status.AUTHORIZED)
                .toList();
    }

    public int countAuthorized() {
        return (int) authorized().size();
    }

    public Optional<ServerPeer> findByPublicKey(String publicKey) {
        return devices.stream().filter(d -> d.publicKey.equals(publicKey)).findFirst();
    }

    public Optional<ServerPeer> findByName(String name) {
        return devices.stream().filter(d -> d.deviceName.equalsIgnoreCase(name)).findFirst();
    }

    public void add(String deviceName, String publicKey, String vpnAddress) {
        for (ServerPeer d : devices) {
            if (d.publicKey.equals(publicKey) || (d.vpnAddress.equals(vpnAddress)
                    && d.status != ServerPeer.Status.REVOKED)) {
                AppLogger.getLogger().warn(LogCategory.SERVER,
                        "device already registered: %s", deviceName);
                // allow re-adding a revoked key? No: reject duplicate public keys.
                if (d.publicKey.equals(publicKey)) {
                    throw new IllegalArgumentException("a device with this key is already registered");
                }
            }
        }
        devices.add(new ServerPeer(deviceName, publicKey, vpnAddress,
                ServerPeer.Status.AUTHORIZED, Instant.now().toString(), null, null));
        persist();
        notifyListeners();
    }

    public void remove(String deviceName) {
        devices.removeIf(d -> d.deviceName.equalsIgnoreCase(deviceName));
        persist();
        notifyListeners();
    }

    public void revoke(String deviceName) {
        for (int i = 0; i < devices.size(); i++) {
            if (devices.get(i).deviceName.equalsIgnoreCase(deviceName)) {
                devices.set(i, devices.get(i).withStatus(ServerPeer.Status.REVOKED));
            }
        }
        persist();
        notifyListeners();
    }

    public void rename(String oldName, String newName) {
        for (int i = 0; i < devices.size(); i++) {
            if (devices.get(i).deviceName.equalsIgnoreCase(oldName)) {
                devices.set(i, devices.get(i).renamed(newName));
            }
        }
        persist();
        notifyListeners();
    }

    public void markOnline(String deviceName) {
        for (int i = 0; i < devices.size(); i++) {
            ServerPeer d = devices.get(i);
            if (d.deviceName.equalsIgnoreCase(deviceName)) {
                devices.set(i, d.withLastSeen(Instant.now().toString()));
            }
        }
    }

    public synchronized void persist() {
        if (file == null) {
            return;
        }
        try {
            Files.createDirectories(file.toAbsolutePath().getParent());
            StringBuilder sb = new StringBuilder("{\"devices\":[");
            boolean first = true;
            for (ServerPeer d : devices) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                sb.append("{\"deviceName\":\"").append(esc(d.deviceName))
                        .append("\",\"publicKey\":\"").append(d.publicKey)
                        .append("\",\"vpnAddress\":\"").append(esc(d.vpnAddress))
                        .append("\",\"status\":\"").append(d.status)
                        .append("\",\"addedAt\":\"").append(esc(d.addedAt))
                        .append("\",\"lastSeenAt\":\"").append(esc(d.lastSeenAt == null ? "" : d.lastSeenAt))
                        .append("\",\"note\":\"").append(esc(d.note == null ? "" : d.note))
                        .append("\"}");
            }
            sb.append("]}");
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            Files.writeString(tmp, sb.toString(), StandardCharsets.UTF_8);
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            AppLogger.getLogger().error(LogCategory.SERVER, e, "client registry write failed");
        }
    }

    private void notifyListeners() {
        for (Listener l : listeners) {
            try {
                l.onDevicesChanged(all());
            } catch (RuntimeException ignored) {
            }
        }
    }

    private static String esc(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}