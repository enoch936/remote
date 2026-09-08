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

    /**
     * Read-only verification of the current NAT/forwarding state. Never makes
     * changes and never throws on a degraded state: the result classifies the
     * situation so the caller can decide whether a failure is real.
     */
    public abstract NatResult verifyNat(String vpnSubnetCidr, String lanInterface);

    /** Check the forwarding/NAT requirements, return a list of administrator actions. */
    public abstract java.util.List<String> missingRequirements(String vpnSubnetCidr, String lanInterface);

    /** Classification of a NAT verification check. */
    public enum State {
        /** Everything the platform can check is in place. */
        VERIFIED,
        /** Partly configured; usually a manual step remains (macOS pf, pending reboot). */
        PARTIAL,
        /** The NAT/forwarding rules this application is responsible for are absent. */
        NOT_ENABLED,
        /** Verification could not be performed at all. */
        ERROR
    }

    /**
     * Result of {@link #verifyNat}. {@code actions} carries the exact
     * administrator steps needed to reach a fully configured state.
     */
    public record NatResult(State state, String summary, java.util.List<String> actions) {

        public boolean isVerified() {
            return state == State.VERIFIED;
        }

        public static NatResult verified(String summary) {
            return new NatResult(State.VERIFIED, summary, java.util.List.of());
        }

        public static NatResult partial(String summary, java.util.List<String> actions) {
            return new NatResult(State.PARTIAL, summary, actions);
        }

        public static NatResult notEnabled(String summary, java.util.List<String> actions) {
            return new NatResult(State.NOT_ENABLED, summary, actions);
        }

        public static NatResult error(String summary) {
            return new NatResult(State.ERROR, summary, java.util.List.of());
        }
    }

    protected NetworkException fail(CommandResult r, String what) {
        AppLogger.getLogger().warn(LogCategory.FIREWALL, "NAT %s failed: %s", what, r.stderr());
        return new NetworkException(NetworkException.Kind.COMMAND_FAILED, what + " failed: " + r.stderr());
    }
}