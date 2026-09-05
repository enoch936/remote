package com.company.remoteaccess.core.configuration;

import com.company.remoteaccess.core.state.Role;
import com.company.remoteaccess.networking.IpHelpers;
import com.company.remoteaccess.networking.IpHelpers.Cidr;

import java.util.ArrayList;
import java.util.List;

/**
 * Pure configuration validation with human-readable issues. Errors block
 * operation; warnings are shown to the user but do not stop startup.
 */
public final class ConfigValidator {

    public static final class Issue {
        public enum Severity { WARNING, ERROR }

        public final Severity severity;
        public final String message;

        public Issue(Severity severity, String message) {
            this.severity = severity;
            this.message = message;
        }
    }

    private ConfigValidator() {
    }

    public static List<Issue> validate(AppConfig cfg) {
        List<Issue> issues = new ArrayList<>();
        if (cfg == null) {
            issues.add(new Issue(Issue.Severity.ERROR, "configuration is missing"));
            return issues;
        }
        Role mode = cfg.mode();
        if (mode == null) {
            issues.add(new Issue(Issue.Severity.ERROR, "mode is not set; run the setup wizard"));
            return issues;
        }
        if (mode == Role.SERVER) {
            validateServer(cfg, issues);
        } else {
            validateClient(cfg, issues);
        }
        validateCommon(cfg, issues);
        return issues;
    }

    private static void validateCommon(AppConfig cfg, List<Issue> issues) {
        if (cfg.tunnelName() == null || cfg.tunnelName().isBlank()) {
            issues.add(new Issue(Issue.Severity.ERROR, "vpn tunnel name is not set"));
        } else if (!cfg.tunnelName().matches("[A-Za-z0-9_-]{1,32}")) {
            issues.add(new Issue(Issue.Severity.ERROR,
                    "vpn tunnel name may only contain letters, digits, '-' and '_'"));
        }
        if (cfg.listenPort() < 1 || cfg.listenPort() > 65535) {
            issues.add(new Issue(Issue.Severity.ERROR, "listen port must be between 1 and 65535"));
        }
        if (!cfg.vpnProvider().equalsIgnoreCase("wireguard")) {
            issues.add(new Issue(Issue.Severity.ERROR, "unsupported VPN provider: "
                    + cfg.vpnProvider()));
        }
        if (!"SPLIT_TUNNEL".equals(cfg.routingMode()) && !"FULL_TUNNEL".equals(cfg.routingMode())) {
            issues.add(new Issue(Issue.Severity.ERROR,
                    "routing.mode must be SPLIT_TUNNEL or FULL_TUNNEL"));
        }
        for (String r : cfg.extraRoutes()) {
            try {
                IpHelpers.parseCidr(r);
            } catch (IllegalArgumentException e) {
                issues.add(new Issue(Issue.Severity.ERROR, "invalid extra route '" + r + "'"));
            }
        }
        if (cfg.maxRetries() < 1 || cfg.maxRetries() > 60) {
            issues.add(new Issue(Issue.Severity.WARNING,
                    "security.maxRetries is out of range; using 5"));
        }
    }

    private static void validateServer(AppConfig cfg, List<Issue> issues) {
        try {
            Cidr vpn = IpHelpers.parseCidr(cfg.vpnSubnet());
            if (vpn.prefix() > 30) {
                issues.add(new Issue(Issue.Severity.ERROR,
                        "VPN subnet is too small (need at least 2 usable addresses)"));
            }
        } catch (IllegalArgumentException e) {
            issues.add(new Issue(Issue.Severity.ERROR, "vpn subnet is invalid: " + cfg.vpnSubnet()));
        }
        if (cfg.lanCidr() != null && !cfg.lanCidr().isBlank()) {
            try {
                IpHelpers.parseCidr(cfg.lanCidr());
            } catch (IllegalArgumentException e) {
                issues.add(new Issue(Issue.Severity.ERROR, "lan subnet is invalid: " + cfg.lanCidr()));
            }
        } else {
            issues.add(new Issue(Issue.Severity.WARNING,
                    "server has no company LAN subnet configured; only the VPN subnet will be routed"));
        }
        String endpoint = cfg.serverPublicEndpoint();
        if (endpoint != null && !endpoint.isBlank()) {
            if (!validEndpoint(endpoint)) {
                issues.add(new Issue(Issue.Severity.ERROR, "public endpoint is invalid: " + endpoint));
            }
        } else if (cfg.serverHost() == null || cfg.serverHost().isBlank()) {
            issues.add(new Issue(Issue.Severity.WARNING,
                    "no discovery endpoint configured; dynamic address mapping will not work"));
        }
    }

    private static void validateClient(AppConfig cfg, List<Issue> issues) {
        if (cfg.clientServerEndpoint() == null || cfg.clientServerEndpoint().isBlank()) {
            issues.add(new Issue(Issue.Severity.ERROR,
                    "the gateway address is not configured; pair the device first"));
        } else if (!validEndpoint(cfg.clientServerEndpoint())) {
            issues.add(new Issue(Issue.Severity.ERROR,
                    "gateway address is invalid: " + cfg.clientServerEndpoint()));
        }
    }

    private static boolean validEndpoint(String endpoint) {
        String host = endpoint.split(":")[0];
        if (host.matches("\\d{1,3}(?:\\.\\d{1,3}){3}")) {
            try {
                IpHelpers.parseIp(host);
                return true;
            } catch (IllegalArgumentException e) {
                return false;
            }
        }
        return host.matches("[A-Za-z0-9.-]+");
    }
}