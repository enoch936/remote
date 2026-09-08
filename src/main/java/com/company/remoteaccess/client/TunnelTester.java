package com.company.remoteaccess.client;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.networking.NetworkManager;
import com.company.remoteaccess.networking.NetworkManager.NetworkSnapshot;
import com.company.remoteaccess.vpn.VpnManager;
import com.company.remoteaccess.vpn.VpnStatus;

import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Runs the post-connect health suite: VPN handshake, assigned address, gateway
 * reachability, DNS, company network, and internet (full tunnel only). Kept
 * non-final so tests can substitute a deterministic double.
 */
public class TunnelTester {

    /** Injectable ping implementation (tests use a fake). */
    public interface Ping {
        boolean reachable(String host, int timeoutMs);
    }

    /** Injectable hostname lookup (tests substitute a fake so no network is used). */
    public interface DnsLookup {
        boolean resolve(String host);

        /** Default: real {@code InetAddress.getByName} lookups. */
        DnsLookup SYSTEM = host -> {
            try {
                InetAddress addr = InetAddress.getByName(host);
                return addr != null && addr.getHostAddress() != null;
            } catch (Exception ignored) {
                return false;
            }
        };
    }

    /** Default ping implementation using the OS ping utility. */
    public static final class OsPing implements Ping {
        private final com.company.remoteaccess.platform.CommandRunner runner;

        public OsPing(com.company.remoteaccess.platform.CommandRunner runner) {
            this.runner = runner;
        }

        @Override
        public boolean reachable(String host, int timeoutMs) {
            var r = com.company.remoteaccess.platform.Os.isWindows()
                    ? runner.run("ping", "-n", "2", "-w", String.valueOf(timeoutMs), host)
                    : runner.run("ping", "-c", "2", "-W", String.valueOf(timeoutMs / 1000 + 1), host);
            boolean ok = r.success() || r.stdout() != null && r.stdout().toLowerCase().contains("ttl=");
            AppLogger.getLogger().debug(LogCategory.VPN,
                    "ping %s -> %s (%dms)", host, ok, timeoutMs);
            return ok;
        }
    }

    private final Ping ping;
    private final NetworkManager network;
    private final DnsLookup dns;

    public TunnelTester(Ping ping, NetworkManager network) {
        this(ping, network, DnsLookup.SYSTEM);
    }

    public TunnelTester(Ping ping, NetworkManager network, DnsLookup dns) {
        Ping fallback = (host, timeoutMs) -> true;
        this.ping = ping == null ? fallback : ping;
        this.network = network;
        this.dns = dns == null ? DnsLookup.SYSTEM : dns;
    }

    /**
     * Run all checks.
     *
     * @param vpn            current tunnel status
     * @param gatewayVpnIp   VPN address of the gateway (server side)
     * @param companyCidr    routed company subnet (or null)
     * @param fullTunnel     whether AllowedIPs covered the internet
     * @param probeHost      internal resource host to probe for "company network reachable"
     */
    public ConnectionReport run(VpnStatus vpn, String gatewayVpnIp,
                                String companyCidr, boolean fullTunnel, String probeHost) {
        List<ConnectionReport.Check> checks = new ArrayList<>();

        checks.add(handshakeCheck(vpn));
        checks.add(vpnIpAssignedCheck(vpn));
        checks.add(gatewayReachableCheck(vpn, gatewayVpnIp));
        checks.add(dnsCheck());
        checks.add(companyNetworkCheck(probeHost));
        if (fullTunnel) {
            checks.add(internetCheck());
        }
        return new ConnectionReport(checks);
    }

    private ConnectionReport.Check handshakeCheck(VpnStatus vpn) {
        boolean ok = vpn != null && vpn.healthy();
        return new ConnectionReport.Check("VPN handshake", ok,
                ok ? "handshake established"
                        : (vpn == null ? "tunnel not running" : "no recent handshake"),
                latencySince(0));
    }

    private ConnectionReport.Check vpnIpAssignedCheck(VpnStatus vpn) {
        boolean ok = vpn != null && vpn.running();
        return new ConnectionReport.Check("VPN IP assigned", ok,
                ok ? "interface " + vpn.tunnelName() + " is up" : "VPN interface not present",
                latencySince(0));
    }

    /**
     * Gateway reachability. A fresh VPN handshake is the authoritative proof the
     * gateway is reachable (the tunnel is clearly passing traffic); ICMP alone is
     * skipped as a verdict so rate-limited or masked ping replies cannot produce a
     * false negative. ICMP is still attempted purely to measure latency.
     */
    private ConnectionReport.Check gatewayReachableCheck(VpnStatus vpn, String gatewayVpnIp) {
        boolean handshake = vpn != null && vpn.healthy();
        if (handshake) {
            long started = System.currentTimeMillis();
            measurePing(gatewayVpnIp);
            return new ConnectionReport.Check("Gateway reachable", true,
                    "VPN handshake established", System.currentTimeMillis() - started);
        }
        if (gatewayVpnIp == null || gatewayVpnIp.isBlank()) {
            return new ConnectionReport.Check("Gateway reachable", false,
                    "gateway VPN IP unknown", 0);
        }
        long started = System.currentTimeMillis();
        boolean reachable = ping.reachable(gatewayVpnIp, 2000);
        return new ConnectionReport.Check("Gateway reachable", reachable,
                reachable ? "gateway responded (no handshake yet)"
                        : "gateway did not respond; handshake not established",
                System.currentTimeMillis() - started);
    }

    private void measurePing(String target) {
        if (target == null || target.isBlank()) {
            return;
        }
        ping.reachable(target, 2000);
    }

    private ConnectionReport.Check dnsCheck() {
        long started = System.currentTimeMillis();
        boolean dnsOk = resolvesAny(inBulk(), dns);
        long ms = System.currentTimeMillis() - started;
        return new ConnectionReport.Check("DNS working", dnsOk,
                dnsOk ? "DNS resolution OK" : "DNS could not resolve", ms);
    }

    private ConnectionReport.Check companyNetworkCheck(String probeHost) {
        if (probeHost == null || probeHost.isBlank()) {
            return new ConnectionReport.Check("Company network", true,
                    "no probe resource configured", 0);
        }
        long started = System.currentTimeMillis();
        boolean ok = ping.reachable(probeHost, 2000);
        return new ConnectionReport.Check("Company network", ok,
                ok ? probeHost + " reachable" : probeHost + " did not respond",
                System.currentTimeMillis() - started);
    }

    private ConnectionReport.Check internetCheck() {
        long started = System.currentTimeMillis();
        boolean ok = ping.reachable("8.8.8.8", 3000)
                || resolvesAny(List.of("www.google.com", "one.one.one.one"), dns);
        return new ConnectionReport.Check("Internet", ok,
                ok ? "external connectivity OK" : "external connectivity failed",
                System.currentTimeMillis() - started);
    }

    /** DNS "bulk": several well-known resolvable names; any hit means DNS works. */
    private static List<String> inBulk() {
        return List.of("www.google.com", "one.one.one.one", "www.cloudflare.com");
    }

    private static boolean resolvesAny(List<String> hosts, DnsLookup dns) {
        ExecutorService pool = Executors.newFixedThreadPool(3);
        try {
            java.util.List<Future<Boolean>> futures = new ArrayList<>();
            for (String h : hosts) {
                futures.add(pool.submit(() -> dns.resolve(h)));
            }
            for (Future<Boolean> f : futures) {
                try {
                    if (f.get(2, TimeUnit.SECONDS)) {
                        return true;
                    }
                } catch (Exception ignored) {
                }
            }
            return false;
        } finally {
            pool.shutdownNow();
        }
    }

    private static long latencySince(long sinceNanos) {
        return (System.nanoTime() - sinceNanos) / 1_000_000L;
    }
}