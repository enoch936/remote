package com.company.remoteaccess.networking;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.platform.CommandResult;
import com.company.remoteaccess.platform.CommandRunner;
import com.company.remoteaccess.platform.Os;
import com.company.remoteaccess.platform.Elevation;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Windows routing adapter built on {@code route.exe}. */
public final class WindowsRouting extends RoutingManager {

    private static final Pattern ROUTE_LINE = Pattern.compile(
            "^(\\d{1,3}(?:\\.\\d{1,3}){3})\\s+(\\d{1,3}(?:\\.\\d{1,3}){3})\\s+(\\S+)\\s+"
                    + "(\\d{1,3}(?:\\.\\d{1,3}){3})\\s+(\\d+)$");

    WindowsRouting(CommandRunner runner, Path manifestPath) {
        super(runner, manifestPath);
    }

    @Override
    public List<RouteEntry> currentRoutes() {
        CommandResult r = runner.run("route", "print", "-4");
        List<RouteEntry> out = new ArrayList<>();
        if (r.stdout() == null) {
            return out;
        }
        boolean inTable = false;
        for (String line : r.lines()) {
            if (line.contains("Network Destination")) {
                inTable = true;
                continue;
            }
            if (!inTable) {
                continue;
            }
            Matcher m = ROUTE_LINE.matcher(line.trim());
            if (!m.matches()) {
                continue;
            }
            String dest = m.group(1);
            String mask = m.group(2);
            String gateway = m.group(3);
            String ifaceIp = m.group(4);
            int metric = Integer.parseInt(m.group(5));
            long maskLong = IpHelpers.parseIp(mask);
            int prefix = Long.bitCount(maskLong);
            boolean isDefault = dest.equals("0.0.0.0") && prefix == 0;
            out.add(new RouteEntry(dest, prefix,
                    gateway.equals("On-link") ? ifaceIp : gateway,
                    ifaceIp, metric, isDefault, false));
        }
        return out;
    }

    @Override
    public void applyPlan(RoutePlan plan) throws NetworkException {
        var issues = RoutePlanValidator.validate(plan);
        boolean fatal = issues.stream().anyMatch(i -> i.severity == RoutePlanValidator.PlanIssue.Severity.ERROR);
        if (fatal) {
            var msg = new StringBuilder("route plan rejected:");
            issues.stream().filter(i -> i.severity == RoutePlanValidator.PlanIssue.Severity.ERROR)
                    .forEach(i -> msg.append("\n - ").append(i.message));
            throw new NetworkException(NetworkException.Kind.NOT_CONFIGURED, msg.toString());
        }
        int ifIndex = interfaceIndex(plan.tunnelInterfaceName());
        if (plan.mode() == RoutePlan.Mode.FULL_TUNNEL) {
            pinEndpointThroughOriginalGateway(plan);
            addManagedRoute(new RouteEntry("0.0.0.0", 0, plan.tunnelGatewayIp(),
                    plan.tunnelInterfaceName(), 5, true, true));
        }
        for (IpHelpers.Cidr c : plan.allRoutedSubnets()) {
            addManagedRoute(new RouteEntry(IpHelpers.format(c.network()), c.prefix(),
                    plan.tunnelGatewayIp(), plan.tunnelInterfaceName(), 5, false, true));
        }
        AppLogger.getLogger().info(LogCategory.ROUTING, "route plan applied (%s)",
                plan.mode() == RoutePlan.Mode.FULL_TUNNEL ? "full tunnel" : "split tunnel");
    }

    @Override
    public void undoPlan(RoutePlan plan) throws NetworkException {
        for (IpHelpers.Cidr c : plan.allRoutedSubnets()) {
            removeManagedRoute(new RouteEntry(IpHelpers.format(c.network()), c.prefix(),
                    plan.tunnelGatewayIp(), plan.tunnelInterfaceName(), 5, false, true));
        }
        if (plan.mode() == RoutePlan.Mode.FULL_TUNNEL) {
            removeManagedRoute(new RouteEntry("0.0.0.0", 0, plan.tunnelGatewayIp(),
                    plan.tunnelInterfaceName(), 5, true, true));
            unpinEndpoint(plan);
        }
        AppLogger.getLogger().info(LogCategory.ROUTING, "route plan undone");
    }

    @Override
    protected void doAddRoute(RouteEntry entry) throws NetworkException {
        ensureElevated();
        String mask = IpHelpers.maskForPrefix(entry.prefix());
        CommandResult r = runner.run("route", "add", entry.network(), "mask", mask, entry.gateway());
        requireZero(r, "route add " + entry.cidr());
        int idx = interfaceIndex(entry.interfaceName());
        if (idx > 0) {
            CommandResult pinned = runner.run("route", "change", entry.network(),
                    entry.gateway(), "if", String.valueOf(idx));
            if (pinned.failed()) {
                AppLogger.getLogger().warn(LogCategory.ROUTING,
                        "route pin to interface %s failed: %s", entry.interfaceName(), pinned.stderr());
            }
        }
    }

    @Override
    protected void doRemoveRoute(RouteEntry entry) throws NetworkException {
        ensureElevated();
        String mask = IpHelpers.maskForPrefix(entry.prefix());
        CommandResult r = runner.run("route", "delete", entry.network(), "mask", mask);
        if (r.failed()) {
            AppLogger.getLogger().warn(LogCategory.ROUTING,
                    "route delete %s reported: %s", entry.cidr(), r.stderr());
        }
    }

    private void pinEndpointThroughOriginalGateway(RoutePlan plan) throws NetworkException {
        String endpointHost = plan.serverPublicEndpoint();
        if (endpointHost == null || !endpointHost.matches("\\d{1,3}(?:\\.\\d{1,3}){3}")) {
            AppLogger.getLogger().warn(LogCategory.ROUTING,
                    "full tunnel without numeric public endpoint; pinning skipped");
            return;
        }
        Optional<String> gw = currentDefaultGateway();
        if (gw.isEmpty()) {
            AppLogger.getLogger().warn(LogCategory.ROUTING,
                    "no original default gateway found; pinning skipped");
            return;
        }
        String gwInterface = currentDefaultInterface(gw.get());
        String host = endpointHost.split(":")[0];
        addManagedRoute(new RouteEntry(host, 32, gw.get(), gwInterface, 1, false, true));
    }

    private void unpinEndpoint(RoutePlan plan) {
        String endpointHost = plan.serverPublicEndpoint();
        if (endpointHost == null || !endpointHost.matches("\\d{1,3}(?:\\.\\d{1,3}){3}")) {
            return;
        }
        try {
            Optional<String> gw = currentDefaultGateway();
            if (gw.isPresent()) {
                removeManagedRoute(new RouteEntry(endpointHost.split(":")[0], 32,
                        gw.get(), "", 1, false, true));
            }
        } catch (NetworkException e) {
            // best effort during teardown
        }
    }

    Optional<String> currentDefaultGateway() {
        return currentRoutes().stream()
                .filter(RouteEntry::isDefault)
                .findFirst()
                .map(RouteEntry::gateway);
    }

    private String currentDefaultInterface(String gatewayOfDefault) {
        // find an interface whose local address sits on the same subnet is overkill;
        // the route table already tells us the interface IP of the default route
        return currentRoutes().stream()
                .filter(RouteEntry::isDefault)
                .findFirst()
                .map(RouteEntry::interfaceName)
                .orElse(null);
    }

    private int interfaceIndex(String name) {
        if (name == null || name.isBlank()) {
            return 0;
        }
        CommandResult r = runner.run("powershell", "-NoProfile", "-Command",
                "(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -eq '" + name + "' } | Select-Object -First 1).InterfaceIndex");
        String out = r.stdout() == null ? "" : r.stdout().trim();
        try {
            return out.isEmpty() ? 0 : Integer.parseInt(out.split("\\r?\\n")[0].trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private void ensureElevated() throws NetworkException {
        if (!Elevation.isElevated()) {
            throw new NetworkException(NetworkException.Kind.PERMISSION_REQUIRED,
                    Elevation.requiredHint("modify routing"));
        }
    }
}