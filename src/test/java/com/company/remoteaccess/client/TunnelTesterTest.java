package com.company.remoteaccess.client;

import com.company.remoteaccess.client.TunnelTester.DnsLookup;
import com.company.remoteaccess.client.TunnelTester.Ping;
import com.company.remoteaccess.vpn.VpnPeer;
import com.company.remoteaccess.vpn.VpnStatus;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TunnelTesterTest {

    private static final String PUB = "P".repeat(43) + "=";

    private final Ping blockedPing = (host, timeoutMs) -> false;
    private final DnsLookup dnsOk = host -> true;
    private final DnsLookup dnsFail = host -> false;

    @Test
    void freshHandshakeMarksGatewayReachableDespiteIcmpFailure() {
        TunnelTester t = new TunnelTester(blockedPing, null, dnsOk);
        ConnectionReport report = t.run(healthyStatus(), "10.50.0.1", "10.50.0.0/24",
                false, null);
        ConnectionReport.Check gateway = check(report, "Gateway reachable");
        assertTrue(gateway.ok(), gateway.detail());
        assertTrue(check(report, "VPN handshake").ok());
    }

    @Test
    void noHandshakeFallsBackToIcmp() {
        TunnelTester ok = new TunnelTester((host, ms) -> true, null, dnsOk);
        ConnectionReport.Check reachable = check(
                ok.run(VpnStatus.down("company0"), "10.50.0.1", null, false, null),
                "Gateway reachable");
        assertTrue(reachable.ok(), reachable.detail());

        TunnelTester blocked = new TunnelTester(blockedPing, null, dnsOk);
        ConnectionReport.Check unreachable = check(
                blocked.run(VpnStatus.down("company0"), "10.50.0.1", null, false, null),
                "Gateway reachable");
        assertFalse(unreachable.ok(), unreachable.detail());
    }

    @Test
    void gatewayReachableWithoutVpnIpIsFailure() {
        TunnelTester t = new TunnelTester(blockedPing, null, dnsOk);
        ConnectionReport.Check g = check(t.run(VpnStatus.down("company0"), null,
                null, false, null), "Gateway reachable");
        assertFalse(g.ok());
    }

    @Test
    void dnsCheckUsesInjectedResolver() {
        TunnelTester badDns = new TunnelTester(blockedPing, null, dnsFail);
        ConnectionReport.Check bad = check(
                badDns.run(VpnStatus.down("company0"), null, null, false, null),
                "DNS working");
        assertFalse(bad.ok());

        TunnelTester goodDns = new TunnelTester(blockedPing, null, dnsOk);
        ConnectionReport.Check good = check(
                goodDns.run(VpnStatus.down("company0"), null, null, false, null),
                "DNS working");
        assertTrue(good.ok());
    }

    @Test
    void probeHostUnreachableFailsCompanyCheck() {
        TunnelTester t = new TunnelTester(blockedPing, null, dnsOk);
        VpnStatus vpn = VpnStatus.down("company0");
        ConnectionReport.Check probe = check(
                t.run(vpn, null, null, false, "intra.company.example"), "Company network");
        assertFalse(probe.ok());
    }

    @Test
    void fullTunnelAddsInternetCheck() {
        TunnelTester t = new TunnelTester(blockedPing, null, dnsOk);
        ConnectionReport split = t.run(healthyStatus(), "10.50.0.1", null, false, null);
        assertTrue(noCheckNamed(split, "Internet"));

        ConnectionReport full = t.run(healthyStatus(), "10.50.0.1", null, true, null);
        ConnectionReport.Check internet = check(full, "Internet");
        assertTrue(internet.ok(), internet.detail());
    }

    private static ConnectionReport.Check check(ConnectionReport r, String name) {
        return r.checks().stream().filter(c -> c.name().equals(name)).findFirst().orElseThrow();
    }

    private static boolean noCheckNamed(ConnectionReport r, String name) {
        return r.checks().stream().noneMatch(c -> c.name().equals(name));
    }

    private static VpnStatus healthyStatus() {
        return new VpnStatus("company0", true, PUB, 51820, null,
                List.of(new VpnPeer(PUB, "10.50.0.1:51820", List.of("10.50.0.0/24"), 5, 1000, 2000)));
    }
}