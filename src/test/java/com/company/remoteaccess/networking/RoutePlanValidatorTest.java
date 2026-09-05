package com.company.remoteaccess.networking;

import com.company.remoteaccess.networking.RoutePlan.Mode;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RoutePlanValidatorTest {

    @Test
    void splitTunnelPlanIsValidWhenComplete() {
        RoutePlan plan = new RoutePlan()
                .mode(Mode.SPLIT_TUNNEL)
                .tunnelInterface("company0", "10.50.0.1")
                .companySubnet(IpHelpers.parseCidr("10.50.0.0/24"))
                .companySubnet(IpHelpers.parseCidr("10.0.0.0/8"));
        List<RoutePlanValidator.PlanIssue> issues = RoutePlanValidator.validate(plan);
        assertTrue(issues.stream().noneMatch(i -> i.severity == RoutePlanValidator.PlanIssue.Severity.ERROR),
                () -> "expected no errors: " + issues);
    }

    @Test
    void missingInterfaceIsFatal() {
        RoutePlan plan = new RoutePlan()
                .mode(Mode.SPLIT_TUNNEL)
                .companySubnet(IpHelpers.parseCidr("10.50.0.0/24"));
        List<RoutePlanValidator.PlanIssue> issues = RoutePlanValidator.validate(plan);
        assertTrue(hasError(issues, "tunnel interface"));
    }

    @Test
    void fullTunnelRequiresPublicEndpoint() {
        RoutePlan plan = new RoutePlan()
                .mode(Mode.FULL_TUNNEL)
                .tunnelInterface("company0", "10.50.0.1")
                .companySubnet(IpHelpers.parseCidr("0.0.0.0/0"));
        List<RoutePlanValidator.PlanIssue> issues = RoutePlanValidator.validate(plan);
        assertTrue(hasError(issues, "gateway public endpoint"));
    }

    @Test
    void fullTunnelCannotRouteGatewayIp() {
        RoutePlan plan = new RoutePlan()
                .mode(Mode.FULL_TUNNEL)
                .tunnelInterface("company0", "10.50.0.1")
                .serverPublicEndpoint("203.0.113.5:51820")
                .extraSubnet(IpHelpers.parseCidr("10.50.0.0/24"));
        List<RoutePlanValidator.PlanIssue> issues = RoutePlanValidator.validate(plan);
        assertTrue(hasError(issues, "through the tunnel"),
                () -> "expected routing-loop error: " + issues);
    }

    @Test
    void emptyCompanySubnetsWarnButDoNotFail() {
        RoutePlan plan = new RoutePlan()
                .mode(Mode.SPLIT_TUNNEL)
                .tunnelInterface("company0", "10.50.0.1")
                .companySubnet(IpHelpers.parseCidr("10.50.0.0/24"));
        List<RoutePlanValidator.PlanIssue> issues = RoutePlanValidator.validate(plan);
        // vpn subnet present means companySubnets non-empty; build a truly empty one:
        RoutePlan empty = new RoutePlan()
                .mode(Mode.SPLIT_TUNNEL)
                .tunnelInterface("company0", "10.50.0.1");
        List<RoutePlanValidator.PlanIssue> e = RoutePlanValidator.validate(empty);
        assertTrue(e.stream().anyMatch(i -> i.severity == RoutePlanValidator.PlanIssue.Severity.WARNING));
    }

    @Test
    void suggestedRoutesCoverSubnets() {
        RoutePlan plan = new RoutePlan()
                .mode(Mode.SPLIT_TUNNEL)
                .tunnelInterface("company0", "10.50.0.1")
                .companySubnet(IpHelpers.parseCidr("10.50.0.0/24"))
                .extraSubnet(IpHelpers.parseCidr("172.16.0.0/12"));
        List<RouteEntry> routes = RoutePlanValidator.suggestedRoutes(plan);
        assertEquals(2, routes.size());
        assertTrue(routes.stream().allMatch(r -> r.gateway().equals("10.50.0.1")));
    }

    @Test
    void nullPlanFails() {
        assertEquals(1, RoutePlanValidator.validate(null).size());
    }

    private static boolean hasError(List<RoutePlanValidator.PlanIssue> issues, String fragment) {
        return issues.stream().anyMatch(i ->
                i.severity == RoutePlanValidator.PlanIssue.Severity.ERROR
                        && i.message.contains(fragment));
    }
}