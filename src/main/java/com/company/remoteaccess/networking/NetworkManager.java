package com.company.remoteaccess.networking;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.platform.CommandResult;
import com.company.remoteaccess.platform.CommandRunner;
import com.company.remoteaccess.platform.Os;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Enumerates, observes and classifies network interfaces. Never mutates
 * configuration; all mutation lives in RoutingManager/FirewallManager/NatManager.
 * (Kept non-final so tests can substitute a deterministic double.)
 */
public class NetworkManager implements AutoCloseable {

    public interface ChangeListener {
        void onNetworkChanged(NetworkSnapshot before, NetworkSnapshot after);
    }

    /** Immutable observation of a detected interface. */
    public record NetworkSnapshot(List<NetInterface> interfaces, boolean online) {
        public static NetworkSnapshot empty() {
            return new NetworkSnapshot(List.of(), false);
        }
    }

    private final CommandRunner runner;
    private final Duration pollInterval;
    private final List<ChangeListener> listeners = new CopyOnWriteArrayList<>();
    private volatile NetworkSnapshot last = NetworkSnapshot.empty();
    private volatile Thread monitor;
    private volatile boolean running;

    public NetworkManager(CommandRunner runner, Duration pollInterval) {
        this.runner = runner;
        this.pollInterval = pollInterval == null ? Duration.ofSeconds(3) : pollInterval;
    }

    public void addChangeListener(ChangeListener l) {
        listeners.add(l);
    }

    public void startMonitor() {
        if (monitor != null && monitor.isAlive()) {
            return;
        }
        running = true;
        monitor = new Thread(this::monitorLoop, "network-monitor");
        monitor.setDaemon(true);
        monitor.start();
        AppLogger.getLogger().info(LogCategory.NETWORK, "network monitor started (interval %ds)",
                pollInterval.toSeconds());
    }

    private void monitorLoop() {
        while (running) {
            try {
                NetworkSnapshot fresh = snapshot();
                if (!java.util.Objects.equals(last, fresh)) {
                    NetworkSnapshot before = last;
                    last = fresh;
                    for (ChangeListener l : listeners) {
                        try {
                            l.onNetworkChanged(before, fresh);
                        } catch (RuntimeException e) {
                            AppLogger.getLogger().error(LogCategory.NETWORK, e, "listener failed");
                        }
                    }
                }
            } catch (Exception e) {
                AppLogger.getLogger().error(LogCategory.NETWORK, e, "network scan failed");
            }
            try {
                Thread.sleep(pollInterval.toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    @Override
    public void close() {
        running = false;
        if (monitor != null) {
            monitor.interrupt();
        }
    }

    public NetworkSnapshot snapshot() {
        return query();
    }

    public NetworkSnapshot lastSnapshot() {
        return last;
    }

    public boolean isOnline() {
        NetworkSnapshot s = snapshot();
        return s.online();
    }

    public List<NetInterface> listInterfaces() {
        return query().interfaces();
    }

    public Optional<NetInterface> findPhysical() {
        return query().interfaces().stream()
                .filter(n -> n.hasIpv4() && (n.type() == NetInterface.Type.ETHERNET
                        || n.type() == NetInterface.Type.WIFI))
                .findFirst();
    }

    public Optional<NetInterface> findByName(String name) {
        return query().interfaces().stream()
                .filter(n -> n.name() != null && n.name().equalsIgnoreCase(name))
                .findFirst();
    }

    public Optional<String> defaultGateway() {
        CommandResult r = runner.run(Os.isWindows()
                ? cmd("powershell", "-NoProfile", "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop")
                : cmd("ip", "route", "show", "default"));
        if (!r.success() || r.stdout() == null || !r.stdout().trim().matches(
                "(?s).*\\d+\\.\\d+\\.\\d+\\.\\d+.*")) {
            return Optional.empty();
        }
        return Optional.of(java.util.regex.Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+")
                .matcher(r.stdout()).results().findFirst()
                .map(m -> m.group())
                .orElse(null))
                .filter(java.util.Objects::nonNull);
    }

    // ------------------------------------------------------------------
    // platform queries
    // ------------------------------------------------------------------

    private NetworkSnapshot query() {
        try {
            List<NetInterface> ifaces = queryInterfaces();
            boolean online = ifaces.stream().anyMatch(n -> n.up() && n.hasIpv4()
                    && (n.type() == NetInterface.Type.ETHERNET || n.type() == NetInterface.Type.WIFI));
            NetworkSnapshot snap = new NetworkSnapshot(
                    Collections.unmodifiableList(ifaces), online);
            if (last.equals(NetworkSnapshot.empty())) {
                last = snap;
            }
            return snap;
        } catch (Exception e) {
            AppLogger.getLogger().error(LogCategory.NETWORK, e, "interface enumeration failed");
            return NetworkSnapshot.empty();
        }
    }

    private List<NetInterface> queryInterfaces() {
        return switch (Os.family()) {
            case WINDOWS -> queryWindows();
            case LINUX -> queryLinux();
            default -> queryLinux();
        };
    }

    private List<NetInterface> queryWindows() {
        String script =
                "Get-NetAdapter | ForEach-Object {" +
                        "  $a = $_;" +
                        "  $ips = Get-NetIPAddress -InterfaceIndex $a.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue;" +
                        "  [PSCustomObject]@{" +
                        "    Index = $a.InterfaceIndex;" +
                        "    Name = $a.Name;" +
                        "    Status = $a.Status.ToString();" +
                        "    Type = ($a | Get-NetAdapterHardwareInfo -ErrorAction SilentlyContinue) | Out-Null; '';" +
                        "    Mac = $a.MacAddress;" +
                        "    Ip = ($ips.IPAddress -join '|')" +
                        "  }" +
                        "} | ConvertTo-Json -Compress";
        // The Type line above is unreliable; re-detect type by name/description.
        script = "Get-NetAdapter | ForEach-Object {" +
                "  $a = $_;" +
                "  $ips = Get-NetIPAddress -InterfaceIndex $a.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue;" +
                "  [PSCustomObject]@{" +
                "    Index = $a.InterfaceIndex;" +
                "    Name = $a.Name;" +
                "    Status = $a.Status.ToString();" +
                "    Desc = $a.InterfaceDescription;" +
                "    Mac = $a.MacAddress;" +
                "    Ip = ($ips.IPAddress -join '|')" +
                "  }" +
                "} | ConvertTo-Json -Compress";
        CommandResult r = runner.run(cmd("powershell", "-NoProfile", "-Command", script));
        if (r.failed() || r.stdout() == null || r.stdout().isBlank()) {
            return parseIpconfig(r);
        }
        return parseWindowsJson(r.stdout());
    }

    private List<NetInterface> parseWindowsJson(String json) {
        List<NetInterface> result = new ArrayList<>();
        try {
            var arr = com.company.remoteaccess.util.Json.parseArray(json);
            for (var obj : arr) {
                String name = obj.get("Name");
                String status = obj.get("Status");
                String desc = obj.get("Desc");
                String mac = obj.get("Mac");
                String ip = obj.get("Ip");
                int index = parseIntSafe(obj.get("Index"));
                boolean up = "Up".equalsIgnoreCase(status);
                List<String> ips = ip == null || ip.isBlank()
                        ? List.of()
                        : java.util.Arrays.stream(ip.split("\\|")).filter(s -> !s.isBlank()).toList();
                NetInterface.Type type = classifyWindows(name, desc);
                result.add(new NetInterface(index, name, type, up, mac, ips, 0));
            }
        } catch (Exception e) {
            AppLogger.getLogger().error(LogCategory.NETWORK, e, "windows JSON parse failed");
        }
        return result;
    }

    private static NetInterface.Type classifyWindows(String name, String desc) {
        String hay = ((name == null ? "" : name) + " " + (desc == null ? "" : desc)).toLowerCase();
        if (hay.contains("wifi") || hay.contains("wi-fi") || hay.contains("wireless")
                || hay.contains("802.11") || hay.contains("wlan")) {
            return NetInterface.Type.WIFI;
        }
        if (hay.contains("wireguard") || hay.contains("tun") || hay.contains("tap")
                || hay.contains("openvpn") || hay.contains("tonnel") || hay.contains("tailscale")) {
            return NetInterface.Type.VPN;
        }
        if (hay.contains("loopback") || name == null || name.startsWith("lo")) {
            return NetInterface.Type.LOOPBACK;
        }
        if (hay.contains("ethernet") || hay.contains("lan") || hay.contains("gigabit")
                || hay.contains("intel") || hay.contains("realtek") || hay.contains("broadcom")
                || hay.contains("vmware") || hay.contains("virtual") || hay.contains("hyper-v")) {
            return NetInterface.Type.ETHERNET;
        }
        return NetInterface.Type.OTHER;
    }

    private List<NetInterface> parseIpconfig(CommandResult r) {
        List<NetInterface> result = new ArrayList<>();
        String out = r.stdout();
        if (out == null) {
            return result;
        }
        String[] blocks = out.split("(?m)^\\s*$");
        for (String block : blocks) {
            String first = block.lines().findFirst().orElse("");
            if (!first.contains("adapter")) {
                continue;
            }
            String name = first.replace("adapter", "").replace(":", "").trim();
            boolean up = !block.contains("Media disconnected");
            List<String> ips = new ArrayList<>();
            for (String line : block.split("\\r?\\n")) {
                String t = line.trim();
                if (t.startsWith("IPv4 Address")) {
                    int i = t.indexOf(':');
                    ips.add(t.substring(i + 1).replace("(Preferred)", "").trim());
                } else if (t.startsWith("Link-local") && ips.isEmpty()) {
                    int i = t.indexOf(':');
                    String ll = t.substring(i + 1).trim();
                    if (ll.startsWith("169.254")) {
                        // ignore auto-config
                    } else {
                        ips.add(ll);
                    }
                }
            }
            result.add(new NetInterface(0, name, classifyWindows(name, ""),
                    up, "", ips, 0));
        }
        return result;
    }

    private List<NetInterface> queryLinux() {
        CommandResult r = runner.run(cmd("ip", "-j", "addr", "show"));
        if (r.failed()) {
            AppLogger.getLogger().warn(LogCategory.NETWORK,
                    "ip -j addr failed (%s); falling back to ip addr", r.stderr());
            return parseIpLinuxPlain(runner.run(cmd("ip", "addr", "show")));
        }
        return parseLinuxJson(r.stdout());
    }

    private List<NetInterface> parseLinuxJson(String json) {
        List<NetInterface> result = new ArrayList<>();
        try {
            var arr = com.company.remoteaccess.util.Json.parseArray(json);
            for (var obj : arr) {
                String name = obj.get("ifname");
                String flags = obj.get("flags");
                int index = parseIntSafe(obj.get("ifindex"));
                boolean up = flags != null && flags.contains(",") && flags.contains("UP");
                NetInterface.Type type = classifyLinux(name);
                List<String> ips = new ArrayList<>();
                var addrInfo = obj.getList("addr_info");
                if (addrInfo != null) {
                    for (var ai : addrInfo) {
                        String family = ai.get("family");
                        if ("inet".equals(family)) {
                            String local = ai.get("local");
                            String prefix = ai.get("prefixlen");
                            if (local != null) {
                                ips.add(prefix == null ? local + "/24" : local + "/" + prefix);
                            }
                        }
                    }
                }
                result.add(new NetInterface(index, name, type, up, null, ips, 0));
            }
        } catch (Exception e) {
            AppLogger.getLogger().error(LogCategory.NETWORK, e, "linux JSON parse failed");
        }
        return result;
    }

    private List<NetInterface> parseIpLinuxPlain(CommandResult r) {
        List<NetInterface> result = new ArrayList<>();
        if (r.stdout() == null) {
            return result;
        }
        for (String line : r.stdout().split("\\r?\\n")) {
            String t = line.trim();
            if (t.startsWith("^") || t.startsWith("#")) {
                continue;
            }
            String name = t.split(":")[1].trim().split("@")[0];
            boolean up = t.contains("state UP");
            result.add(new NetInterface(0, name, classifyLinux(name), up, null, List.of(), 0));
        }
        return result;
    }

    private static NetInterface.Type classifyLinux(String name) {
        if (name == null) {
            return NetInterface.Type.OTHER;
        }
        String n = name.toLowerCase();
        if (n.startsWith("w") && n.length() > 1 && Character.isLetter(n.charAt(1))) {
            return NetInterface.Type.WIFI;
        }
        if (n.startsWith("eth") || n.startsWith("enp") || n.startsWith("ens")
                || n.startsWith("eno") || n.startsWith("em")) {
            return NetInterface.Type.ETHERNET;
        }
        if (n.startsWith("wg") || n.startsWith("tun") || n.startsWith("tap")) {
            return NetInterface.Type.VPN;
        }
        if (n.startsWith("lo")) {
            return NetInterface.Type.LOOPBACK;
        }
        return NetInterface.Type.OTHER;
    }

    private static int parseIntSafe(String s) {
        try {
            return s == null ? 0 : Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static java.util.List<String> cmd(String... parts) {
        return java.util.Arrays.asList(parts);
    }
}