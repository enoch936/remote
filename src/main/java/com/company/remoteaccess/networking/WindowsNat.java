package com.company.remoteaccess.networking;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.platform.CommandResult;
import com.company.remoteaccess.platform.CommandRunner;
import com.company.remoteaccess.platform.Elevation;

import java.util.List;

/**
 * Windows NAT adapter using WinNAT (New-NetNat) plus the IP-Enable-Router switch.
 * Requires an elevated session; a reboot informs WinNAT of the new NAT.
 */
public final class WindowsNat extends NatManager {

    public static final String NAT_NAME = "CompanyRemoteNAT";

    WindowsNat(CommandRunner runner) {
        super(runner);
    }

    @Override
    public void enableNat(String vpnSubnetCidr, String lanInterface, String lanCidr)
            throws NetworkException {
        ensureElevated();
        CommandResult nat = runner.run("powershell", "-NoProfile", "-Command",
                "New-NetNat -Name '" + NAT_NAME + "' -InternalIPInterfaceAddressPrefix '"
                        + vpnSubnetCidr + "' -ErrorAction Stop");
        if (nat.failed()) {
            if (nat.stderr() != null && nat.stderr().toLowerCase().contains("alreadyExists")) {
                AppLogger.getLogger().info(LogCategory.FIREWALL, "NAT %s already present", NAT_NAME);
            } else {
                throw fail(nat, "create NetNat");
            }
        }
        CommandResult router = runner.run("powershell", "-NoProfile", "-Command",
                "New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' "
                        + "-Name 'IPEnableRouter' -Value 1 -PropertyType DWord -Force");
        if (router.failed()) {
            throw new NetworkException(NetworkException.Kind.PERMISSION_REQUIRED,
                    "Unable to enable IP forwarding (IPEnableRouter). "
                            + "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\IPEnableRouter=1 "
                            + "as Administrator and reboot, or disable Full-Tunnel mode.");
        }
        String returnAction = "Note: a reboot may be required for WinNAT to route VPN traffic "
                + "to '" + lanInterface + "'.";
        throw new NetworkException(NetworkException.Kind.PERMISSION_REQUIRED,
                "NAT configured. " + returnAction);
    }

    @Override
    public void disableNat(String vpnSubnetCidr, String lanInterface, String lanCidr)
            throws NetworkException {
        ensureElevated();
        CommandResult r = runner.run("powershell", "-NoProfile", "-Command",
                "Remove-NetNat -Name '" + NAT_NAME + "' -Confirm:$false -ErrorAction SilentlyContinue");
        if (r.failed()) {
            AppLogger.getLogger().warn(LogCategory.FIREWALL, "Remove-NetNat: %s", r.stderr());
        }
    }

    @Override
    public boolean isEnabled() {
        CommandResult r = runner.run("powershell", "-NoProfile", "-Command",
                "(Get-NetNat -Name '" + NAT_NAME + "' -ErrorAction SilentlyContinue) -ne $null");
        return r.success() && r.stdout() != null && r.stdout().trim().equalsIgnoreCase("true");
    }

    @Override
    public List<String> missingRequirements(String vpnSubnetCidr, String lanInterface) {
        List<String> actions = new java.util.ArrayList<>();
        if (!Elevation.isElevated()) {
            actions.add("Run the application as Administrator to configure NAT/forwarding.");
        }
        if (isEnabled()) {
            return actions;
        }
        actions.add("Create Windows NetNat '" + NAT_NAME + "' with internal prefix "
                + vpnSubnetCidr + " (New-NetNat).");
        actions.add("Set IPEnableRouter=1 in HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters.");
        actions.add("Reboot so WinNAT starts routing the VPN subnet toward " + lanInterface + ".");
        return actions;
    }

    private void ensureElevated() throws NetworkException {
        if (!Elevation.isElevated()) {
            throw new NetworkException(NetworkException.Kind.PERMISSION_REQUIRED,
                    Elevation.requiredHint("configure NAT and IP forwarding"));
        }
    }
}