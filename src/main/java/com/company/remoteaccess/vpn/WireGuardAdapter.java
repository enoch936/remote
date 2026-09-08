package com.company.remoteaccess.vpn;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.platform.CommandResult;
import com.company.remoteaccess.platform.CommandRunner;
import com.company.remoteaccess.platform.Elevation;
import com.company.remoteaccess.platform.FilePermissions;
import com.company.remoteaccess.platform.Os;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Real WireGuard adapter. Shells out to the audited WireGuard tooling
 * ({@code wg}, {@code wg-quick}, and on Windows the official client's
 * {@code wireguard.exe} tunnel service). No cryptography or VPN protocol
 * logic is implemented here.
 *
 * <ul>
 *   <li>Windows: tunnel is installed as a service ({@code wireguard.exe
 *       /installtunnelservice}) and controlled with {@code sc}.</li>
 *   <li>Linux/macOS: {@code wg-quick up/down}.</li>
 *   <li>Status/reporting: {@code wg show}.</li>
 * </ul>
 */
public final class WireGuardAdapter implements VpnAdapter {

    private static final Pattern INTERFACE_LINE = Pattern.compile("interface:\\s+(\\S+)");
    private static final Pattern PEER_LINE = Pattern.compile("peer:\\s+(\\S+)");
    private static final Pattern KEY_LINE = Pattern.compile("\\b(public|private)\\s+key:\\s+(\\S+)");
    private static final Pattern PORT_LINE = Pattern.compile("listening\\s+port:\\s+(\\d+)");
    private static final Pattern ENDPOINT_LINE = Pattern.compile("endpoint:\\s+(\\S+)");
    private static final Pattern ALLOWED_LINE = Pattern.compile("allowed\\s+ips:\\s+(.+)");
    private static final Pattern HANDSHAKE_LINE = Pattern.compile("latest\\s+handshake:\\s+(\\d+)\\s+.*ago");
    private static final Pattern TRANSFER_LINE = Pattern.compile("transfer:\\s+(\\S+)\\s+received,\\s+(\\S+)\\s+sent");

    private final CommandRunner runner;
    private final Path managedDir;
    private final String wgBinary;
    private final String wireGuardExe;   // null on non-Windows
    private final String wgQuick;        // null on Windows

    public WireGuardAdapter(CommandRunner runner, Path managedDir,
                            String wgBinary, String wireGuardExe, String wgQuick) {
        this.runner = runner;
        this.managedDir = managedDir;
        this.wgBinary = wgBinary;
        this.wireGuardExe = wireGuardExe;
        this.wgQuick = wgQuick;
    }

    public static WireGuardAdapter build(CommandRunner runner, Path managedDir,
                                         String configuredBinaryDir) throws VpnException {
        Optional<String> wg = KeyManager.findWgBinary(runner, configuredBinaryDir);
        if (wg.isEmpty()) {
            throw new VpnException(VpnException.Kind.BINARIES_MISSING,
                    "WireGuard (wg) is not installed or not on PATH.");
        }
        String wireGuardExe = null;
        String wgQuick = null;
        if (Os.isWindows()) {
            String pf = System.getenv("ProgramFiles");
            Path exe = Path.of((pf == null ? "C:\\Program Files" : pf), "WireGuard", "wireguard.exe");
            if (Files.exists(exe)) {
                wireGuardExe = exe.toAbsolutePath().toString();
            }
        } else {
            wgQuick = firstExecutable("/usr/bin/wg-quick", "/usr/local/bin/wg-quick",
                    "/opt/homebrew/bin/wg-quick", "/opt/local/bin/wg-quick");
            if (wgQuick == null) {
                CommandResult which = runner.run("which", "wg-quick");
                if (which.success() && which.stdout() != null && !which.stdout().isBlank()) {
                    wgQuick = which.stdout().lines().findFirst().orElse("").trim();
                }
            }
        }
        if (Os.isWindows() && wireGuardExe == null) {
            throw new VpnException(VpnException.Kind.BINARIES_MISSING,
                    "WireGuard for Windows (wireguard.exe) is not installed.");
        }
        if (!Os.isWindows() && wgQuick == null) {
            throw new VpnException(VpnException.Kind.BINARIES_MISSING,
                    "wg-quick is not installed (install wireguard-tools).");
        }
        return new WireGuardAdapter(runner, managedDir, wg.get(), wireGuardExe, wgQuick);
    }

    @Override
    public void ensureAvailable() throws VpnException {
        CommandResult r = runner.run(wgBinary, "version");
        if (r.failed()) {
            throw new VpnException(VpnException.Kind.BINARIES_MISSING,
                    "wg binary is not runnable (exit " + r.exitCode() + "): "
                            + trim(r.stderr()));
        }
        AppLogger.getLogger().info(LogCategory.VPN, "WireGuard detected (%s)", wgBinary);
    }

    @Override
    public boolean isInstalled(String tunnelName) {
        if (Os.isWindows()) {
            return wireGuardExe != null && isServicePresent(tunnelName);
        }
        return Files.exists(Path.of("/etc/wireguard", tunnelName + ".conf"));
    }

    @Override
    public boolean isRunning(String tunnelName) {
        if (Os.isWindows()) {
            if (!isServicePresent(tunnelName)) {
                return false;
            }
            CommandResult r = runner.run("sc", "query", serviceName(tunnelName));
            return r.success() && r.stdout() != null && r.stdout().contains("RUNNING");
        }
        VpnStatus s = status(tunnelName);
        return s != null && s.running();
    }

    @Override
    public void ensureInstalled(String tunnelName) throws VpnException {
        if (isInstalled(tunnelName)) {
            AppLogger.getLogger().info(LogCategory.VPN,
                    "tunnel %s already installed; reusing existing service", tunnelName);
            return;
        }
        loadConfig(tunnelName);
    }

    @Override
    public void ensureRunning(String tunnelName) throws VpnException {
        if (isRunning(tunnelName)) {
            AppLogger.getLogger().info(LogCategory.VPN,
                    "tunnel %s already running; verifying state", tunnelName);
            verifyConfig(tunnelName);
            return;
        }
        if (!isInstalled(tunnelName)) {
            ensureInstalled(tunnelName);
        }
        start(tunnelName);
    }

    @Override
    public void verifyConfig(String tunnelName) throws VpnException {
        Path conf = managedDir.resolve(tunnelName + ".conf");
        if (Os.isWindows() && !configMatches(tunnelName, conf)) {
            AppLogger.getLogger().warn(LogCategory.VPN,
                    "running tunnel %s does not match the expected configuration", tunnelName);
            throw new VpnException(VpnException.Kind.CONFIGURATION_ERROR,
                    "tunnel " + tunnelName + " is running with a different configuration");
        }
    }

    @Override
    public void writeConfig(String tunnelName, String configText) throws VpnException {
        try {
            Files.createDirectories(managedDir);
            Path conf = managedDir.resolve(tunnelName + ".conf");
            Files.writeString(conf, configText, StandardCharsets.UTF_8);
            FilePermissions.hardenFile(conf);
            AppLogger.getLogger().info(LogCategory.VPN,
                    "tunnel configuration written for %s (secrets protected)", tunnelName);
        } catch (IOException e) {
            throw new VpnException(VpnException.Kind.CONFIGURATION_ERROR,
                    "unable to write tunnel config: " + e.getMessage(), e);
        }
    }

    @Override
    public void loadConfig(String tunnelName) throws VpnException {
        if (Os.isWindows()) {
            if (wireGuardExe == null) {
                throw new VpnException(VpnException.Kind.BINARIES_MISSING,
                        "wireguard.exe is not available");
            }
            ensureElevated("install the VPN tunnel");
            Path conf = managedDir.resolve(tunnelName + ".conf");
            if (!Files.exists(conf)) {
                throw new VpnException(VpnException.Kind.CONFIGURATION_ERROR,
                        "tunnel config missing for " + tunnelName);
            }
            if (isServicePresent(tunnelName)) {
                if (configMatches(tunnelName, conf)) {
                    AppLogger.getLogger().info(LogCategory.VPN,
                            "tunnel %s already installed with matching config; reusing", tunnelName);
                    return;
                }
                AppLogger.getLogger().info(LogCategory.VPN,
                        "tunnel %s installed but configuration changed; reinstalling", tunnelName);
                removeServiceQuietly(tunnelName);
            }
            CommandResult r = runner.run(wireGuardExe, "/installtunnelservice", conf.toString());
            if (r.failed()) {
                throw new VpnException(VpnException.Kind.CONFIGURATION_ERROR,
                        "WireGuard service install failed (exit " + r.exitCode() + "): "
                                + trim(r.stderr()));
            }
            AppLogger.getLogger().info(LogCategory.VPN,
                    "WireGuard tunnel service installed: %s", tunnelName);
        } else {
            ensureRoot("install the VPN tunnel config");
            try {
                Files.createDirectories(Path.of("/etc/wireguard"));
                Path conf = Path.of("/etc/wireguard", tunnelName + ".conf");
                Path staged = managedDir.resolve(tunnelName + ".conf");
                byte[] bytes = Files.readAllBytes(staged);
                if (Files.exists(conf)
                        && Arrays.equals(bytes, Files.readAllBytes(conf))) {
                    AppLogger.getLogger().info(LogCategory.VPN,
                            "tunnel %s already installed; reusing existing config", tunnelName);
                    return;
                }
                Files.write(conf, bytes);
                FilePermissions.hardenFile(conf);
                AppLogger.getLogger().info(LogCategory.VPN,
                        "wg-quick config installed at %s", conf);
            } catch (IOException e) {
                throw new VpnException(VpnException.Kind.CONFIGURATION_ERROR,
                        "unable to install /etc/wireguard config: " + e.getMessage(), e);
            }
        }
    }

    @Override
    public void start(String tunnelName) throws VpnException {
        ensureAvailable();
        if (Os.isWindows()) {
            ensureElevated("start the VPN tunnel");
            if (isRunning(tunnelName)) {
                AppLogger.getLogger().info(LogCategory.VPN,
                        "tunnel %s already running; reusing existing service", tunnelName);
                return;
            }
            if (!isServicePresent(tunnelName)) {
                ensureInstalled(tunnelName);
            }
            CommandResult r = runner.run("sc", "start", serviceName(tunnelName));
            if (r.failed()) {
                throw new VpnException(VpnException.Kind.START_FAILED,
                        String.format("unable to start WireGuard tunnel: service=%s exit=%d stderr=%s",
                                serviceName(tunnelName), r.exitCode(), trim(r.stderr())));
            }
            waitForService(tunnelName, true, 30);
        } else {
            ensureRoot("start the VPN tunnel");
            if (tunnelAlreadyUp(listTunnels(), tunnelName)) {
                AppLogger.getLogger().info(LogCategory.VPN,
                        "tunnel %s already up; reusing existing interface", tunnelName);
            } else {
                CommandResult r = runner.run(wgQuick, "up", tunnelName);
                if (r.failed()) {
                    throw new VpnException(VpnException.Kind.START_FAILED,
                            "wg-quick up failed: " + r.stderr());
                }
            }
            if (Os.isMacos()) {
                flushDnsCache();
            }
        }
        AppLogger.getLogger().info(LogCategory.VPN, "tunnel started: %s", tunnelName);
    }

    /** Currently existing interfaces (from {@code wg show interfaces}). */
    public List<String> listTunnels() {
        CommandResult r = runner.run(wgBinary, "show", "interfaces");
        if (r.failed() || r.stdout() == null) {
            return List.of();
        }
        return parseInterfaces(r.stdout());
    }

    static List<String> parseInterfaces(String raw) {
        if (raw == null) {
            return List.of();
        }
        return raw.lines().map(String::trim).filter(s -> !s.isEmpty()).toList();
    }

    static boolean tunnelAlreadyUp(List<String> tunnels, String tunnelName) {
        return tunnels != null && tunnelName != null
                && tunnels.stream().anyMatch(tunnelName::equals);
    }

    /** macOS: DNS servers supplied by wg-quick are applied by the resolver only
     *  after a cache flush; a stale cache otherwise holds the pre-tunnel answers. */
    private void flushDnsCache() {
        CommandResult dscache = runner.run("dscacheutil", "-flushcache");
        CommandResult mdns = runner.run("killall", "-HUP", "mDNSResponder");
        boolean anyOk = dscache.success() || mdns.success();
        if (anyOk) {
            AppLogger.getLogger().debug(LogCategory.VPN,
                    "macOS DNS cache flushed after tunnel start");
        } else {
            AppLogger.getLogger().warn(LogCategory.VPN,
                    "macOS DNS cache flush reported failures: %s | %s",
                    dscache.stderr(), mdns.stderr());
        }
    }

    @Override
    public void stop(String tunnelName) throws VpnException {
        if (Os.isWindows()) {
            if (!isServicePresent(tunnelName)) {
                AppLogger.getLogger().info(LogCategory.VPN, "tunnel not installed; nothing to stop");
                return;
            }
            if (!isRunning(tunnelName)) {
                AppLogger.getLogger().info(LogCategory.VPN, "tunnel already stopped; nothing to stop");
                return;
            }
            CommandResult r = runner.run("sc", "stop", serviceName(tunnelName));
            if (r.failed()) {
                AppLogger.getLogger().warn(LogCategory.VPN,
                        "sc stop reported (exit %d): %s", r.exitCode(), trim(r.stderr()));
            }
            waitForService(tunnelName, false, 30);
        } else {
            if (!tunnelAlreadyUp(listTunnels(), tunnelName)) {
                AppLogger.getLogger().info(LogCategory.VPN,
                        "tunnel %s not up; nothing to stop", tunnelName);
                return;
            }
            CommandResult r = runner.run(wgQuick, "down", tunnelName);
            if (r.failed() && r.stderr() != null && !r.stderr().contains("not exist")) {
                AppLogger.getLogger().warn(LogCategory.VPN,
                        "wg-quick down (exit %d): %s", r.exitCode(), trim(r.stderr()));
            }
        }
        AppLogger.getLogger().info(LogCategory.VPN, "tunnel stopped: %s", tunnelName);
    }

    /** Uninstall the Windows tunnel service entirely (used during reconfiguration). */
    @Override
    public void removeConfig(String tunnelName) throws VpnException {
        if (Os.isWindows()) {
            ensureElevated("remove the VPN tunnel service");
            removeServiceQuietly(tunnelName);
        } else {
            try {
                Files.deleteIfExists(Path.of("/etc/wireguard", tunnelName + ".conf"));
            } catch (IOException e) {
                AppLogger.getLogger().warn(LogCategory.VPN, "remove config: %s", e.getMessage());
            }
        }
    }

    @Override
    public VpnStatus status(String tunnelName) {
        CommandResult r = runner.run(wgBinary, "show", tunnelName);
        if (r.failed() || r.stdout() == null) {
            return VpnStatus.down(tunnelName);
        }
        String out = r.stdout();
        Matcher iface = INTERFACE_LINE.matcher(out);
        if (!iface.find()) {
            return VpnStatus.down(tunnelName);
        }
        boolean running = iface.group(1).equals(tunnelName);
        String publicKey = null;
        Integer port = null;
        String privateKey = null;
        List<VpnPeer> peers = new ArrayList<>();

        String currentPeer = null;
        String peerEndpoint = null;
        String peerAllowed = "";
        long handshake = -1;
        long rx = 0;
        long tx = 0;

        for (String line : out.split("\\r?\\n")) {
            String t = line.trim();
            Matcher km = KEY_LINE.matcher(t);
            if (km.find()) {
                if (!km.group(1).equals("private")) {
                    publicKey = km.group(2);
                } else if (km.group(1).equals("private")) {
                    privateKey = km.group(2);
                }
                continue;
            }
            Matcher pm = PORT_LINE.matcher(t);
            if (pm.find()) {
                port = Integer.parseInt(pm.group(1));
                continue;
            }
            Matcher peerM = PEER_LINE.matcher(t);
            if (peerM.find()) {
                flushPeer(peers, currentPeer, peerEndpoint, peerAllowed, handshake, rx, tx);
                currentPeer = peerM.group(1);
                peerEndpoint = null;
                peerAllowed = "";
                handshake = -1;
                rx = 0;
                tx = 0;
                continue;
            }
            Matcher em = ENDPOINT_LINE.matcher(t);
            if (em.find()) {
                peerEndpoint = em.group(1);
                continue;
            }
            Matcher am = ALLOWED_LINE.matcher(t);
            if (am.find()) {
                peerAllowed = am.group(1).trim();
                continue;
            }
            Matcher hm = HANDSHAKE_LINE.matcher(t);
            if (hm.find()) {
                handshake = Long.parseLong(hm.group(1));
                continue;
            }
            Matcher tm = TRANSFER_LINE.matcher(t);
            if (tm.find()) {
                rx = parseSize(tm.group(1));
                tx = parseSize(tm.group(2));
            }
        }
        flushPeer(peers, currentPeer, peerEndpoint, peerAllowed, handshake, rx, tx);

        return new VpnStatus(tunnelName, running, publicKey,
                port == null ? 0 : port,
                "hidden".equalsIgnoreCase(privateKey == null ? "" : privateKey) ? null : privateKey,
                List.copyOf(peers));
    }

    /** Add or update a peer on a live tunnel. */
    public void setPeer(String tunnelName, String publicKey, String allowedIps) throws VpnException {
        ensureElevatedDynamic("modify a live tunnel peer");
        CommandResult r = runner.run(wgBinary, "set", tunnelName,
                "peer", publicKey, "allowed-ips", allowedIps);
        if (r.failed()) {
            throw new VpnException(VpnException.Kind.CONFIGURATION_ERROR,
                    "wg set peer failed: " + r.stderr());
        }
        AppLogger.getLogger().info(LogCategory.VPN, "peer updated live on %s", tunnelName);
    }

    /** Remove a peer from a live tunnel (revocation). */
    public void removePeer(String tunnelName, String publicKey) throws VpnException {
        ensureElevatedDynamic("revoke a live tunnel peer");
        CommandResult r = runner.run(wgBinary, "set", tunnelName, "peer", publicKey, "remove");
        if (r.failed()) {
            throw new VpnException(VpnException.Kind.CONFIGURATION_ERROR,
                    "wg set peer remove failed: " + r.stderr());
        }
        AppLogger.getLogger().info(LogCategory.VPN, "peer revoked on live tunnel %s", tunnelName);
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private static String serviceName(String tunnelName) {
        return "WireGuardTunnel$" + tunnelName;
    }

    /**
     * Compare the staged configuration against the installed tunnel: public key
     * (derived from the expected private key) and, when fixed, the listen port.
     * Never logs key material.
     */
    private boolean configMatches(String tunnelName, Path conf) {
        try {
            String expectedPrivate = privateKeyFrom(conf);
            if (expectedPrivate == null) {
                return false;
            }
            CommandResult pub = runner.runWithInput(List.of(wgBinary, "pubkey"),
                    expectedPrivate + "\n", 30);
            if (pub.failed() || pub.stdout() == null || pub.stdout().isBlank()) {
                return false;
            }
            String expectedPublic = pub.stdout().trim();
            VpnStatus current = status(tunnelName);
            if (current == null || !current.running() || current.publicKey() == null
                    || !expectedPublic.equals(current.publicKey())) {
                return false;
            }
            Integer expectedPort = listenPortFrom(conf);
            if (expectedPort != null && expectedPort != 0
                    && current.listenPort() != 0 && expectedPort != current.listenPort()) {
                return false;
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static String privateKeyFrom(Path conf) {
        return valueFromLine(conf, ".*PrivateKey\\s*=\\s*(\\S+)\\s*");
    }

    private static Integer listenPortFrom(Path conf) {
        String v = valueFromLine(conf, ".*ListenPort\\s*=\\s*(\\d+)\\s*");
        if (v == null) {
            return null;
        }
        try {
            return Integer.parseInt(v);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String valueFromLine(Path conf, String regex) {
        try {
            for (String line : Files.readAllLines(conf, StandardCharsets.UTF_8)) {
                Matcher m = Pattern.compile(regex).matcher(line);
                if (m.matches()) {
                    return m.group(1);
                }
            }
        } catch (IOException ignored) {
        }
        return null;
    }

    private static String trim(String s) {
        return s == null ? "" : s.trim();
    }

    private static String firstExecutable(String... candidates) {
        for (String c : candidates) {
            Path p = Path.of(c);
            if (Files.isExecutable(p)) {
                return p.toAbsolutePath().toString();
            }
        }
        return null;
    }

    private boolean isServicePresent(String tunnelName) {
        CommandResult r = runner.run("sc", "query", serviceName(tunnelName));
        return r.success();
    }

    private void removeServiceQuietly(String tunnelName) {
        if (wireGuardExe == null) {
            return;
        }
        CommandResult stop = runner.run("sc", "stop", serviceName(tunnelName));
        if (stop.failed()) {
            AppLogger.getLogger().debug(LogCategory.VPN, "sc stop: %s", stop.stderr());
        }
        CommandResult uninstall = runner.run(wireGuardExe, "/uninstalltunnelservice", tunnelName);
        if (uninstall.failed()) {
            AppLogger.getLogger().debug(LogCategory.VPN,
                    "wireguard /uninstalltunnelservice: %s", uninstall.stderr());
        }
    }

    private void waitForService(String tunnelName, boolean expectRunning, int timeoutSeconds)
            throws VpnException {
        long deadline = System.currentTimeMillis() + timeoutSeconds * 1000L;
        while (System.currentTimeMillis() < deadline) {
            CommandResult r = runner.run("sc", "query", serviceName(tunnelName));
            boolean running = r.stdout() != null && r.stdout().contains("RUNNING");
            if (running == expectRunning) {
                return;
            }
            lazySleep(700);
        }
        throw new VpnException(VpnException.Kind.TIMEOUT,
                String.format("WireGuard service did not reach the expected state: service=%s "
                                + "expectRunning=%s timeout=%ds",
                        serviceName(tunnelName), expectRunning, timeoutSeconds));
    }

    private static void lazySleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void ensureElevated(String operation) throws VpnException {
        if (!Elevation.isElevated()) {
            throw new VpnException(VpnException.Kind.PERMISSION_REQUIRED,
                    "Administrator privileges are required to " + operation + ".");
        }
    }

    private void ensureElevatedDynamic(String operation) throws VpnException {
        if (!Elevation.isElevated() && !Os.isWindows()) {
            throw new VpnException(VpnException.Kind.PERMISSION_REQUIRED,
                    "Root privileges are required to " + operation + ".");
        }
    }

    private void ensureRoot(String operation) throws VpnException {
        boolean isRoot = Os.isWindows()
                || "0".equals(System.getProperty("user.name", ""));
        if (!isRoot) {
            throw new VpnException(VpnException.Kind.PERMISSION_REQUIRED,
                    "Root privileges are required to " + operation + ".");
        }
    }

    private static void flushPeer(List<VpnPeer> peers, String pk, String ep,
                                  String allowed, long handshake, long rx, long tx) {
        if (pk == null) {
            return;
        }
        List<String> ips = java.util.Arrays.stream(allowed.split(","))
                .map(String::trim).filter(s -> !s.isEmpty()).toList();
        peers.add(new VpnPeer(pk, ep, ips, handshake, rx, tx));
    }

    private static long parseSize(String s) {
        try {
            String t = s.trim();
            if (t.endsWith("KiB")) {
                return Math.round(Double.parseDouble(t.substring(0, t.length() - 3)) * 1024);
            }
            if (t.endsWith("MiB")) {
                return Math.round(Double.parseDouble(t.substring(0, t.length() - 3)) * 1024 * 1024);
            }
            if (t.endsWith("GiB")) {
                return Math.round(Double.parseDouble(t.substring(0, t.length() - 3)) * 1024 * 1024 * 1024);
            }
            if (t.endsWith("B")) {
                return Long.parseLong(t.substring(0, t.length() - 1));
            }
            return Long.parseLong(t.replace("B", ""));
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}