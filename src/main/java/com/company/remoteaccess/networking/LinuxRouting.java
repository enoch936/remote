package com.company.remoteaccess.networking;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.platform.CommandResult;
import com.company.remoteaccess.platform.CommandRunner;
import com.company.remoteaccess.platform.Elevation;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Linux routing adapter built on {@code ip route}. */
public final class LinuxRouting extends RoutingManager {

    private static final Pattern CIDR = Pattern.compile(
            "^(\\d{1,3}(?:\\.\\d{1,3}){3})/(\\d{1,2})");

    LinuxRouting(CommandRunner runner, Path manifestPath) {
        super(runner, manifestPath);
    }

    @Override
    public List<RouteEntry> currentRoutes() {
        CommandResult r = runner.run("ip", "route", "show");
        List<RouteEntry> out = new ArrayList<>();
        if (r.stdout() == null) {
            return out;
        }
        for (String line : r.lines()) {
            String t = line.trim();
            if (t.isEmpty()) {
                continue;
            }
            boolean isDefault = t.startsWith("default");
            String target;
            String gw = null;
            String dev = null;
            int metric = 0;
            if (isDefault) {
                target = "0.0.0.0";
                Matcher vm = Pattern.compile("\\bvia\\s+(\\S+)").matcher(t);
                if (vm.find()) {
                    gw = vm.group(1);
                }
                Matcher dm = Pattern.compile("\\bdev\\s+(\\S+)").matcher(t);
                if (dm.find()) {
                    dev = dm.group(1);
                }
                Matcher mm = Pattern.compile("\\bmetric\\s+(\\d+)").matcher(t);
                if (mm.find()) {
                    metric = Integer.parseInt(mm.group(1));
                }
                out.add(new RouteEntry(target, 0, gw, dev, metric, true, false));
            } else {
                Matcher m = CIDR.matcher(t);
                if (!m.find()) {
                    continue;
                }
                String net = m.group(1);
                int prefix = Integer.parseInt(m.group(2));
                Matcher vm = Pattern.compile("\\bvia\\s+(\\S+)").matcher(t);
                if (vm.find()) {
                    gw = vm.group(1);
                }
                Matcher dm = Pattern.compile("\\bdev\\s+(\\S+)").matcher(t);
                if (dm.find()) {
                    dev = dm.group(1);
                }
                Matcher mm = Pattern.compile("\\bmetric\\s+.*|\\bmetric\\s+(\\d+)").matcher(t);
                if (mm.find() && mm.group(1) != null) {
                    metric = Integer.parseInt(mm.group(1));
                }
                out.add(new RouteEntry(net, prefix, gw, dev, metric, false, false));
            }
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
        for (IpHelpers.Cidr c : plan.allRoutedSubnets()) {
            addManagedRoute(new RouteEntry(IpHelpers.format(c.network()), c.prefix(),
                    plan.tunnelGatewayIp(), plan.tunnelInterfaceName(), 0, false, true));
        }
        if (plan.mode() == RoutePlan.Mode.FULL_TUNNEL) {
            String epHost = plan.serverPublicEndpoint();
            if (epHost != null && epHost.matches("\\d{1,3}(?:\\.\\d{1,3}){3}")) {
                String oldGw = currentDefaultGateway().orElse(null);
                String oldDev = currentDefaultDevice().orElse(plan.tunnelInterfaceName());
                if (oldGw != null) {
                    runner.run("ip", "route", "add", epHost.split(":")[0] + "/32",
                            "via", oldGw, "dev", oldDev);
                    runner.run("ip", "route", "change", epHost.split(":")[0] + "/32",
                            "via", oldGw, "dev", oldDev);
                }
            }
            addManagedRoute(new RouteEntry("0.0.0.0", 0, null,
                    plan.tunnelInterfaceName(), 10, true, true));
        }
        AppLogger.getLogger().info(LogCategory.ROUTING, "route plan applied (%s)",
                plan.mode() == RoutePlan.Mode.FULL_TUNNEL ? "full tunnel" : "split tunnel");
    }

    @Override
    public void undoPlan(RoutePlan plan) throws NetworkException {
        for (IpHelpers.Cidr c : plan.allRoutedSubnets()) {
            removeManagedRoute(new RouteEntry(IpHelpers.format(c.network()), c.prefix(),
                    plan.tunnelGatewayIp(), plan.tunnelInterfaceName(), 0, false, true));
        }
        if (plan.mode() == RoutePlan.Mode.FULL_TUNNEL) {
            removeManagedRoute(new RouteEntry("0.0.0.0", 0, null,
                    plan.tunnelInterfaceName(), 10, true, true));
            String epHost = plan.serverPublicEndpoint();
            if (epHost != null && epHost.matches("\\d{1,3}(?:\\.\\d{1,3}){3}")) {
                runner.run("ip", "route", "del", epHost.split(":")[0] + "/32");
            }
        }
        AppLogger.getLogger().info(LogCategory.ROUTING, "route plan undone");
    }

    @Override
    protected void doAddRoute(RouteEntry entry) throws NetworkException {
        ensureElevated();
        String cidr = entry.network() + "/" + entry.prefix();
        CommandResult r;
        if (entry.isDefault()) {
            r = runner.run("ip", "route", "add", "default", "dev", entry.interfaceName(),
                    "metric", String.valueOf(entry.metric() == 0 ? 10 : entry.metric()));
        } else if (entry.gateway() != null) {
            r = runner.run("ip", "route", "add", cidr, "via", entry.gateway(),
                    "dev", entry.interfaceName());
        } else {
            r = runner.run("ip", "route", "add", cidr, "dev", entry.interfaceName());
        }
        if (r.failed() && r.stderr() != null && r.stderr().contains("File exists")) {
            AppLogger.getLogger().info(LogCategory.ROUTING, "route %s already present", cidr);
        } else {
            requireZero(r, "ip route add " + cidr);
        }
    }

    @Override
    protected void doRemoveRoute(RouteEntry entry) throws NetworkException {
        ensureElevated();
        String cidr = entry.network() + "/" + entry.prefix();
        CommandResult r;
        if (entry.isDefault()) {
            r = runner.run("ip", "route", "del", "default", "dev", entry.interfaceName(),
                    "metric", String.valueOf(entry.metric() == 0 ? 10 : entry.metric()));
        } else if (entry.gateway() != null) {
            r = runner.run("ip", "route", "del", cidr, "via", entry.gateway(),
                    "dev", entry.interfaceName());
        } else {
            r = runner.run("ip", "route", "del", cidr);
        }
        if (r.failed()) {
            AppLogger.getLogger().warn(LogCategory.ROUTING,
                    "ip route del %s reported: %s", cidr, r.stderr());
        }
    }

    private java.util.Optional<String> currentDefaultGateway() {
        return currentRoutes().stream().filter(RouteEntry::isDefault)
                .map(RouteEntry::gateway).filter(java.util.Objects::nonNull).findFirst();
    }

    private java.util.Optional<String> currentDefaultDevice() {
        return currentRoutes().stream().filter(RouteEntry::isDefault)
                .map(RouteEntry::interfaceName).filter(java.util.Objects::nonNull).findFirst();
    }

    private void ensureElevated() throws NetworkException {
        if (!Elevation.isElevated()) {
            throw new NetworkException(NetworkException.Kind.PERMISSION_REQUIRED,
                    Elevation.requiredHint("modify routing"));
        }
    }
}