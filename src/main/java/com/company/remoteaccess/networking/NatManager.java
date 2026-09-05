package com.company.remoteaccess.networking;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.platform.CommandResult;
import com.company.remoteaccess.platform.CommandRunner;
import com.company.remoteaccess.platform.Elevation;
import com.company.remoteaccess.platform.Os;

import java.nio.file.Path;

/**
 * Server-side NAT / internet sharing (needed only for FULL_TUNNEL deployments).
 *
 * <p>Verifies that IP forwarding is enabled, NAT exists and return traffic is
 * permitted. Whenever a requirement cannot be configured automatically it is
 * reported as an explicit administrator action instead of failing silently.
 */
public abstract class NatManager {

    protected final CommandRunner runner;

    protected NatManager(CommandRunner runner) {
        this.runner = runner;
    }

    public static NatManager forPlatform(CommandRunner runner) {
        return switch (Os.family()) {
            case WINDOWS -> new WindowsNat(runner);
            case MACOS -> new MacOsNat(runner);
            default -> new LinuxNat(runner);
        };
    }

    /** Apply NAT + forwarding for full-tunnel traffic toward the given LAN interface. */
    public abstract void enableNat(String vpnSubnetCidr, String lanInterface, String lanCidr)
            throws NetworkException;

    /** Remove everything enableNat() added. */
    public abstract void disableNat(String vpnSubnetCidr, String lanInterface, String lanCidr)
            throws NetworkException;

    /** True when forwarding appears to be enabled (best effort). */
    public abstract boolean isEnabled();

    /** Check the forwarding/NAT requirements, return a list of administrator actions. */
    public abstract java.util.List<String> missingRequirements(String vpnSubnetCidr, String lanInterface);

    protected NetworkException fail(CommandResult r, String what) {
        AppLogger.getLogger().warn(LogCategory.FIREWALL, "NAT %s failed: %s", what, r.stderr());
        return new NetworkException(NetworkException.Kind.COMMAND_FAILED, what + " failed: " + r.stderr());
    }
}