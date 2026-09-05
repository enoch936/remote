package com.company.remoteaccess.networking;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.platform.CommandResult;
import com.company.remoteaccess.platform.CommandRunner;
import com.company.remoteaccess.platform.Elevation;

import java.util.List;

/** Linux NAT adapter: sysctl forwarding + iptables MASQUERADE. */
public final class LinuxNat extends NatManager {

    LinuxNat(CommandRunner runner) {
        super(runner);
    }

    @Override
    public void enableNat(String vpnSubnetCidr, String lanInterface, String lanCidr)
            throws NetworkException {
        ensureElevated();
        CommandResult fwd = runner.run("sysctl", "-w", "net.ipv4.ip_forward=1");
        if (fwd.failed()) {
            throw fail(fwd, "enable ip_forward");
        }
        CommandResult masq = runner.run("iptables", "-C", "POSTROUTING",
                "-t", "nat", "-s", vpnSubnetCidr, "-o", lanInterface, "-j", "MASQUERADE");
        CommandResult add;
        if (masq.success()) {
            add = masq;
        } else {
            add = runner.run("iptables", "-A", "POSTROUTING",
                    "-t", "nat", "-s", vpnSubnetCidr, "-o", lanInterface, "-j", "MASQUERADE");
        }
        if (add.failed()) {
            throw fail(add, "create MASQUERADE rule");
        }
        CommandResult forward = runner.run("iptables", "-C", "FORWARD", "-i", "wg+", "-j", "ACCEPT");
        if (forward.failed()) {
            runner.run("iptables", "-A", "FORWARD", "-i", "wg+", "-j", "ACCEPT");
        }
        AppLogger.getLogger().info(LogCategory.FIREWALL,
                "NAT enabled: %s -> %s via MASQUERADE", vpnSubnetCidr, lanInterface);
    }

    @Override
    public void disableNat(String vpnSubnetCidr, String lanInterface, String lanCidr)
            throws NetworkException {
        ensureElevated();
        CommandResult r = runner.run("iptables", "-D", "POSTROUTING",
                "-t", "nat", "-s", vpnSubnetCidr, "-o", lanInterface, "-j", "MASQUERADE");
        if (r.failed()) {
            AppLogger.getLogger().warn(LogCategory.FIREWALL, "iptables -D POSTROUTING: %s", r.stderr());
        }
        CommandResult forward = runner.run("iptables", "-D", "FORWARD", "-i", "wg+", "-j", "ACCEPT");
        if (forward.failed()) {
            AppLogger.getLogger().debug(LogCategory.FIREWALL, "no wg+ FORWARD rule to remove");
        }
    }

    @Override
    public boolean isEnabled() {
        CommandResult r = runner.run("sysctl", "-n", "net.ipv4.ip_forward");
        return r.success() && "1".equals(r.stdout() == null ? "" : r.stdout().trim());
    }

    @Override
    public List<String> missingRequirements(String vpnSubnetCidr, String lanInterface) {
        List<String> actions = new java.util.ArrayList<>();
        if (!Elevation.isElevated()) {
            actions.add("Run the application with sudo to configure NAT/forwarding.");
            return actions;
        }
        if (!isEnabled()) {
            actions.add("Enable net.ipv4.ip_forward=1 (sysctl -w net.ipv4.ip_forward=1).");
        }
        actions.add("Add iptables MASQUERADE for " + vpnSubnetCidr + " on " + lanInterface + ".");
        return actions;
    }

    private void ensureElevated() throws NetworkException {
        if (!Elevation.isElevated()) {
            throw new NetworkException(NetworkException.Kind.PERMISSION_REQUIRED,
                    Elevation.requiredHint("configure NAT and forwarding"));
        }
    }
}