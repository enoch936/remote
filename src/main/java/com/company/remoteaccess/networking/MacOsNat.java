package com.company.remoteaccess.networking;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.platform.CommandResult;
import com.company.remoteaccess.platform.CommandRunner;
import com.company.remoteaccess.platform.Elevation;

import java.util.ArrayList;
import java.util.List;

/**
 * macOS NAT adapter.
 *
 * <p>Enables IP forwarding automatically (sysctl) and reports the exact pf rule the
 * administrator must add to NAT full-tunnel traffic. macOS pairs a single VPN subnet
 * with a pf anchor; the application never rewrites the user's /etc/pf.conf because a
 * failed pf reload could drop their whole firewall.
 */
public final class MacOsNat extends NatManager {

    MacOsNat(CommandRunner runner) {
        super(runner);
    }

    @Override
    public void enableNat(String vpnSubnetCidr, String lanInterface, String lanCidr)
            throws NetworkException {
        ensureElevated();
        CommandResult fwd = runner.run("sysctl", "-w", "net.inet.ip.forwarding=1");
        if (fwd.failed()) {
            throw fail(fwd, "enable IP forwarding");
        }
        AppLogger.getLogger().info(LogCategory.FIREWALL,
                "IP forwarding enabled; NAT on macOS requires this pf rule (add manually): "
                        + "nat on %s from %s to any -> %s",
                lanInterface, vpnSubnetCidr, lanInterface);
    }

    @Override
    public void disableNat(String vpnSubnetCidr, String lanInterface, String lanCidr)
            throws NetworkException {
        // The pf NAT rule is added by the administrator, not by this application.
        AppLogger.getLogger().info(LogCategory.FIREWALL,
                "remove the manual pf NAT rule for %s on %s, if desired",
                vpnSubnetCidr, lanInterface);
    }

    @Override
    public boolean isEnabled() {
        CommandResult r = runner.run("sysctl", "-n", "net.inet.ip.forwarding");
        return r.success() && "1".equals(r.stdout() == null ? "" : r.stdout().trim());
    }

    @Override
    public List<String> missingRequirements(String vpnSubnetCidr, String lanInterface) {
        List<String> actions = new ArrayList<>();
        if (!Elevation.isElevated()) {
            actions.add("Run the application with administrator rights to enable IP forwarding.");
        }
        if (!isEnabled()) {
            actions.add("Enable net.inet.ip.forwarding=1 (sysctl -w net.inet.ip.forwarding=1).");
        }
        actions.add("Add the pf NAT rule for " + vpnSubnetCidr + " on " + lanInterface + " "
                + "(see the logs/dashboard for the exact nat on line).");
        return actions;
    }

    @Override
    public NatResult verifyNat(String vpnSubnetCidr, String lanInterface) {
        boolean forwarding;
        try {
            CommandResult r = runner.run("sysctl", "-n", "net.inet.ip.forwarding");
            forwarding = r.success() && "1".equals(r.stdout() == null ? "" : r.stdout().trim());
        } catch (Exception e) {
            return NatResult.error("unable to read sysctl net.inet.ip.forwarding: " + e.getMessage());
        }
        if (!forwarding) {
            return NatResult.notEnabled("net.inet.ip.forwarding is not enabled; full-tunnel traffic is not routed",
                    missingRequirements(vpnSubnetCidr, lanInterface));
        }
        // pf NAT rules are intentionally managed by the administrator; the pf
        // state cannot be queried component-wise the way sysctl can, so this is
        // by-design a partial verification and does not block the gateway.
        return NatResult.partial("IP forwarding enabled; the pf NAT rule is manual and cannot be verified automatically (nat on "
                + lanInterface + " from " + vpnSubnetCidr + " to any -> " + lanInterface + ")",
                java.util.List.of("Add the pf NAT rule shown in the dashboard/logs to NAT full-tunnel traffic."));
    }

    private void ensureElevated() throws NetworkException {
        if (!Elevation.isElevated()) {
            throw new NetworkException(NetworkException.Kind.PERMISSION_REQUIRED,
                    Elevation.requiredHint("enable IP forwarding"));
        }
    }
}