package com.company.remoteaccess.networking;

import com.company.remoteaccess.networking.RoutePlan.Mode;

import java.util.ArrayList;
import java.util.List;

/**
 * Pure validation and route calculation. Unit-testable without any OS calls.
 */
public final class RoutePlanValidator {

    public static final class PlanIssue {
        public enum Severity { WARNING, ERROR }

        public final Severity severity;
        public final String message;

        public PlanIssue(Severity severity, String message) {
            this.severity = severity;
            this.message = message;
        }
    }

    private RoutePlanValidator() {
    }

    /** Validate a plan before it is ever applied to the system. */
    public static List<PlanIssue> validate(RoutePlan plan) {
        List<PlanIssue> issues = new ArrayList<>();
        if (plan == null) {
            issues.add(new PlanIssue(PlanIssue.Severity.ERROR, "plan is null"));
            return issues;
        }
        if (plan.tunnelInterfaceName() == null || plan.tunnelInterfaceName().isBlank()) {
            issues.add(new PlanIssue(PlanIssue.Severity.ERROR, "tunnel interface is not set"));
        }
        if (plan.tunnelGatewayIp() == null || !isVpnAddressPlausible(plan.tunnelGatewayIp())) {
            issues.add(new PlanIssue(PlanIssue.Severity.ERROR, "tunnel gateway IP is invalid: "
                    + plan.tunnelGatewayIp()));
        }
        if (plan.mode() == Mode.FULL_TUNNEL) {
            String ep = plan.serverPublicEndpoint();
            if (ep == null || ep.isBlank()) {
                issues.add(new PlanIssue(PlanIssue.Severity.ERROR,
                        "full tunnel requires the gateway public endpoint to pin it out of the tunnel"));
            }
            issues.add(new PlanIssue(PlanIssue.Severity.WARNING,
                    "full tunnel routes all internet traffic through the company gateway"));
        }
        if (plan.companySubnets().isEmpty()) {
            issues.add(new PlanIssue(PlanIssue.Severity.WARNING,
                    "no company subnets configured; only direct VPN subnet will be reachable"));
        }
        for (IpHelpers.Cidr c : plan.allRoutedSubnets()) {
            if (c.prefix() < 1 || c.prefix() > 32) {
                issues.add(new PlanIssue(PlanIssue.Severity.ERROR, "invalid routed subnet: " + c));
            }
        }
        // guard against routing loops: never route the tunnel/gateway subnet through itself
        if (plan.mode() == Mode.FULL_TUNNEL) {
            for (IpHelpers.Cidr c : plan.allRoutedSubnets()) {
                long gw = IpHelpers.parseIp(plan.tunnelGatewayIp());
                if (c.contains(gw)) {
                    issues.add(new PlanIssue(PlanIssue.Severity.ERROR,
                            "route plan would route the VPN gateway through the tunnel (" + c + ")"));
                }
            }
        }
        return issues;
    }

    /** Suggested routes for the plan. Used for pre-flight reporting and tests. */
    public static List<RouteEntry> suggestedRoutes(RoutePlan plan) {
        List<RouteEntry> routes = new ArrayList<>();
        for (IpHelpers.Cidr c : plan.allRoutedSubnets()) {
            routes.add(new RouteEntry(IpHelpers.format(c.network()), c.prefix(),
                    plan.tunnelGatewayIp(), plan.tunnelInterfaceName(), 5, false, true));
        }
        return routes;
    }

    private static boolean isVpnAddressPlausible(String ip) {
        try {
            long parsed = IpHelpers.parseIp(ip);
            // reject loopback and link-local
            return !(parsed >> 24 == 127L) && (parsed >> 24 != 169L);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}