package com.company.remoteaccess.networking;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.platform.CommandRunner;
import com.company.remoteaccess.platform.Os;
import com.company.remoteaccess.util.Json;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Creates and removes only the minimum firewall rules required by the
 * application. All rules are named with an application prefix and recorded in a
 * manifest so only our own rules are ever removed. The system firewall is never
 * disabled.
 */
public abstract class FirewallManager {

    protected final CommandRunner runner;
    private final Path manifestPath;
    private final List<FirewallRule> applied = new ArrayList<>();

    protected FirewallManager(CommandRunner runner, Path manifestPath) {
        this.runner = runner;
        this.manifestPath = manifestPath;
        loadManifest();
    }

    public static FirewallManager forPlatform(CommandRunner runner, Path manifestPath) {
        return switch (Os.family()) {
            case WINDOWS -> new WindowsFirewall(runner, manifestPath);
            case MACOS -> new MacOSFirewall(runner, manifestPath);
            default -> new LinuxFirewall(runner, manifestPath);
        };
    }

    public abstract void applyRule(FirewallRule rule) throws NetworkException;

    public abstract void removeRuleById(String id) throws NetworkException;

    /** Remove every rule this application has created. Used on uninstall. */
    public synchronized void removeAllManaged() {
        List<FirewallRule> rules = new ArrayList<>(applied);
        for (FirewallRule r : rules) {
            try {
                removeRuleById(r.id());
            } catch (NetworkException e) {
                AppLogger.getLogger().warn(LogCategory.FIREWALL,
                        "could not remove rule %s: %s", r.id(), e.getMessage());
            }
        }
        applied.clear();
        persistManifest();
    }

    public List<FirewallRule> appliedRules() {
        return List.copyOf(applied);
    }

    protected synchronized void record(FirewallRule rule) {
        applied.removeIf(r -> r.id().equals(rule.id()));
        applied.add(rule);
        persistManifest();
        AppLogger.getLogger().info(LogCategory.FIREWALL,
                "firewall rule applied: %s (%s, %s port %s, %s)", rule.id(), rule.purpose(),
                rule.protocol(), rule.localPort() == null ? "-" : rule.localPort(), rule.direction());
    }

    protected synchronized void forget(String id) {
        applied.removeIf(r -> r.id().equals(id));
        persistManifest();
    }

    private void persistManifest() {
        try {
            if (manifestPath == null) {
                return;
            }
            Files.createDirectories(manifestPath.toAbsolutePath().getParent());
            StringBuilder sb = new StringBuilder("{\"rules\":[");
            boolean first = true;
            for (FirewallRule r : applied) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                sb.append("{\"id\":\"").append(r.id())
                        .append("\",\"purpose\":\"").append(r.purpose())
                        .append("\",\"protocol\":\"").append(r.protocol())
                        .append("\",\"port\":").append(r.localPort() == null ? "null" : r.localPort())
                        .append(",\"direction\":\"").append(r.direction())
                        .append("\",\"action\":\"").append(r.action())
                        .append("\",\"remote\":\"").append(r.remoteCidr() == null ? "" : r.remoteCidr())
                        .append("\",\"created\":\"").append(r.createdAt())
                        .append("\",\"version\":\"").append(r.appVersion())
                        .append("\"}");
            }
            sb.append("]}");
            Files.writeString(manifestPath, sb.toString(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            AppLogger.getLogger().error(LogCategory.FIREWALL, e, "firewall manifest write failed");
        }
    }

    private void loadManifest() {
        if (manifestPath == null || !Files.exists(manifestPath)) {
            return;
        }
        try {
            String json = Files.readString(manifestPath, StandardCharsets.UTF_8);
            var obj = Json.parseObject(json);
            var list = obj.getList("rules");
            if (list == null) {
                return;
            }
            for (var r : list) {
                Integer port = r.get("port") == null ? null : Integer.parseInt(r.get("port"));
                applied.add(new FirewallRule(
                        r.get("id"),
                        r.get("purpose"),
                        FirewallRule.Protocol.valueOf(r.get("protocol")),
                        port,
                        FirewallRule.Direction.valueOf(r.get("direction")),
                        FirewallRule.Action.valueOf(r.get("action")),
                        r.get("remote"),
                        r.get("created"),
                        r.get("version")));
            }
        } catch (Exception e) {
            AppLogger.getLogger().error(LogCategory.FIREWALL, e, "firewall manifest read failed");
        }
    }
}