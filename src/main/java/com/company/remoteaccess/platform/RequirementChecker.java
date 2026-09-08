package com.company.remoteaccess.platform;

import com.company.remoteaccess.vpn.KeyManager;

import java.util.ArrayList;
import java.util.List;

/**
 * Reports whether the platform is ready to run as a gateway or client:
 * supported OS, WireGuard tooling, administrator rights and persisted
 * configuration.
 */
public final class RequirementChecker {

    public enum Status { OK, MISSING, PERMISSION, UNSUPPORTED }

    public record Requirement(String id, String label, Status status, String detail) {
    }

    private RequirementChecker() {
    }

    /** Pure evaluation of the supplied facts (deterministic, unit-testable). */
    public static List<Requirement> evaluate(boolean osSupported, boolean wgPresent,
                                             boolean elevated, boolean adminRequired,
                                             boolean appConfigured) {
        List<Requirement> out = new ArrayList<>();
        out.add(new Requirement("os",
                "Operating system support",
                osSupported ? Status.OK : Status.UNSUPPORTED,
                osSupported ? Os.family().name() : "unsupported platform"));

        Status wgStatus = wgPresent ? Status.OK : Status.MISSING;
        String wgDetail = wgPresent
                ? "WireGuard tooling found"
                : "WireGuard (wg) not found - install it for VPN operations";
        out.add(new Requirement("wg", "WireGuard tooling", wgStatus, wgDetail));

        if (adminRequired) {
            Status perm = elevated ? Status.OK : Status.PERMISSION;
            out.add(new Requirement("elevation",
                    "Administrator privileges",
                    perm,
                    elevated ? "running elevated"
                            : "restart with elevation: " + Elevation.requiredHint("manage the VPN")));
        } else {
            out.add(new Requirement("elevation",
                    "Administrator privileges",
                    Status.OK,
                    "not required for this session"));
        }

        out.add(new Requirement("config",
                "App configuration",
                appConfigured ? Status.OK : Status.MISSING,
                appConfigured ? "configuration present"
                        : "no configuration yet - run the setup wizard"));
        return out;
    }

    /** Live survey for the current process. */
    public static List<Requirement> survey(CommandRunner runner, String wgBinaryDir,
                                           boolean adminRequired, boolean appConfigured) {
        boolean osSupported = Os.family() != Os.Family.OTHER;
        String wgDir = wgBinaryDir == null ? "" : wgBinaryDir;
        boolean wgPresent = KeyManager.findWgBinary(runner, wgDir).isPresent();
        return evaluate(osSupported, wgPresent, Elevation.isElevated(), adminRequired, appConfigured);
    }

    /** Short one-line summary of the survey, for startup logs. */
    public static String summarize(List<Requirement> requirements) {
        StringBuilder sb = new StringBuilder();
        for (Requirement r : requirements) {
            if (sb.length() > 0) {
                sb.append("; ");
            }
            sb.append(r.id()).append('=').append(r.status().name().toLowerCase());
        }
        return sb.toString();
    }
}