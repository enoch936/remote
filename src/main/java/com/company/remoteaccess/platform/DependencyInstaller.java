package com.company.remoteaccess.platform;

import java.util.List;
import java.util.Optional;

/**
 * Best-effort, one-click dependency management. Turns a missing platform tool
 * (currently WireGuard) into an automatic install command; running the plan
 * usually needs an elevated session, so the app relaunches itself elevated for
 * the fix (see {@link Elevation} and the {@code --fix-requirements} flow).
 */
public final class DependencyInstaller {

    /**
     * @param label           human-readable description (also used in logs)
     * @param command         commands to run; empty means "manual install required"
     * @param requiresElevation whether the plan must run in an elevated session
     */
    public record Plan(String label, List<String> command, boolean requiresElevation) {

        public boolean automatic() {
            return command != null && !command.isEmpty();
        }
    }

    private DependencyInstaller() {
    }

    /**
     * Install plan for the missing WireGuard tooling on this platform.
     * {@code winget present} is probed on Windows so the plan is accurate.
     */
    public static Optional<Plan> wireGuardInstallPlan(CommandRunner runner) {
        switch (Os.family()) {
            case WINDOWS: {
                boolean winget = runner != null && runner.run("winget", "--version").success();
                if (winget) {
                    return Optional.of(new Plan("Install WireGuard with winget",
                            List.of("winget", "install", "-e", "--id", "WireGuard.WireGuard",
                                    "--accept-package-agreements", "--accept-source-agreements"),
                            true));
                }
                return Optional.of(new Plan("WireGuard is not installed; install it from wireguard.com",
                        List.of(), true));
            }
            case LINUX:
                return Optional.of(new Plan("Install wireguard-tools",
                        List.of("bash", "-c",
                                "apt-get update -qq && "
                                        + "(apt-get install -y wireguard-tools || dnf -y install wireguard-tools)"),
                        true));
            case MACOS:
                return Optional.of(new Plan("Install wireguard-tools with Homebrew",
                        List.of("brew", "install", "wireguard-tools"), true));
            default:
                return Optional.empty();
        }
    }

    /** Plain-language guidance shown when no automatic plan exists or install fails. */
    public static String manualHint() {
        return switch (Os.family()) {
            case WINDOWS -> "Install WireGuard from https://www.wireguard.com/install/ "
                    + "then restart this application.";
            case LINUX -> "Install wireguard-tools with your package manager "
                    + "(apt/dnf) as root, then restart this application.";
            case MACOS -> "Install WireGuard tools (brew install wireguard-tools "
                    + "or the Mac App Store app), then restart this application.";
            default -> "Install WireGuard tooling, then restart this application.";
        };
    }
}