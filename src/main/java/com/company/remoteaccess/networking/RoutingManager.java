package com.company.remoteaccess.networking;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.platform.CommandResult;
import com.company.remoteaccess.platform.CommandRunner;
import com.company.remoteaccess.platform.Os;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Applies and reverses application-managed routes without touching pre-existing
 * routing configuration. Concrete OS behavior is delegated to subclasses.
 */
public abstract class RoutingManager {

    protected final CommandRunner runner;
    private final RouteManifest manifest;

    protected RoutingManager(CommandRunner runner, Path manifestPath) {
        this.runner = runner;
        this.manifest = new RouteManifest(manifestPath);
        try {
            manifest.load();
        } catch (IllegalStateException e) {
            AppLogger.getLogger().error(LogCategory.ROUTING, e, "route manifest problem");
        }
    }

    public static RoutingManager forPlatform(CommandRunner runner, Path manifestPath) {
        return switch (Os.family()) {
            case WINDOWS -> new WindowsRouting(runner, manifestPath);
            default -> new LinuxRouting(runner, manifestPath);
        };
    }

    public RouteManifest manifest() {
        return manifest;
    }

    /** Full table, including routes the application previously added. */
    public abstract List<RouteEntry> currentRoutes();

    public abstract void applyPlan(RoutePlan plan) throws NetworkException;

    public abstract void undoPlan(RoutePlan plan) throws NetworkException;

    /** Undo every route the application has ever created (disconnect/cleanup). */
    public synchronized void undoAllManaged() throws NetworkException {
        List<RouteEntry> remaining = new ArrayList<>(manifest.all());
        for (RouteEntry r : remaining) {
            removeManagedRoute(r);
        }
        manifest.clear();
    }

    protected synchronized void addManagedRoute(RouteEntry entry) throws NetworkException {
        AppLogger.getLogger().info(LogCategory.ROUTING,
                "adding managed route %s via %s (%s), default=%s",
                entry.cidr(), entry.gateway(), entry.interfaceName(), entry.isDefault());
        doAddRoute(entry);
        manifest.add(entry);
    }

    protected synchronized void removeManagedRoute(RouteEntry entry) throws NetworkException {
        AppLogger.getLogger().info(LogCategory.ROUTING,
                "removing managed route %s via %s (%s)",
                entry.cidr(), entry.gateway(), entry.interfaceName());
        doRemoveRoute(entry);
        manifest.remove(entry);
    }

    protected abstract void doAddRoute(RouteEntry entry) throws NetworkException;

    protected abstract void doRemoveRoute(RouteEntry entry) throws NetworkException;

    protected void assertPersistedRouteExists(RouteEntry entry) {
        // marker for future use; route may be re-created by network restore
    }

    protected CommandResult win(String... command) {
        return runner.run(List.of(Arrays_join(command)));
    }

    private static String Arrays_join(String... parts) {
        return String.join(" ", parts);
    }

    protected NetworkException fail(NetworkException.Kind kind, CommandResult r, String what) {
        AppLogger.getLogger().warn(LogCategory.ROUTING, "%s failed: %s", what, r.stderr());
        return new NetworkException(kind, what + " failed: " + r.stderr());
    }

    protected void requireZero(CommandResult r, String what) throws NetworkException {
        if (r.failed()) {
            throw fail(NetworkException.Kind.COMMAND_FAILED, r, what);
        }
    }
}