package com.company.remoteaccess.networking;

import com.company.remoteaccess.platform.CommandResult;
import com.company.remoteaccess.platform.CommandRunner;
import com.company.remoteaccess.platform.Elevation;

import java.nio.file.Path;

/** Linux firewall adapter (iptables or ufw). Requires root rights. */
public final class LinuxFirewall extends FirewallManager {

    LinuxFirewall(CommandRunner runner, Path manifestPath) {
        super(runner, manifestPath);
    }

    @Override
    public void applyRule(FirewallRule rule) throws NetworkException {
        ensureElevated();
        CommandResult r;
        if (rule.protocol() == FirewallRule.Protocol.ICMP) {
            r = runner.run("iptables", "-I", "INPUT", "-p", "icmp", "-j",
                    rule.action() == FirewallRule.Action.ALLOW ? "ACCEPT" : "DROP",
                    "-m", "comment", "--comment", rule.displayName());
        } else {
            String proto = rule.protocol() == FirewallRule.Protocol.ANY ? "all" : rule.protocol().name().toLowerCase();
            String chain = rule.direction() == FirewallRule.Direction.IN ? "INPUT" : "OUTPUT";
            var args = new java.util.ArrayList<String>();
            args.addAll(java.util.List.of("iptables", "-I", chain, "-p", proto));
            if (rule.localPort() != null) {
                args.addAll(java.util.List.of("--dport", String.valueOf(rule.localPort())));
            }
            if (rule.remoteCidr() != null && !rule.remoteCidr().isBlank()) {
                args.addAll(java.util.List.of("-s", rule.remoteCidr()));
            }
            args.addAll(java.util.List.of("-j", rule.action() == FirewallRule.Action.ALLOW ? "ACCEPT" : "DROP",
                    "-m", "comment", "--comment", rule.displayName()));
            r = runner.run(args);
        }
        if (r.failed()) {
            throw new NetworkException(NetworkException.Kind.COMMAND_FAILED,
                    "iptables rule could not be added: " + r.stderr());
        }
        record(rule);
    }

    @Override
    public void removeRuleById(String id) throws NetworkException {
        ensureElevated();
        CommandResult r = runner.run("iptables", "-D", "INPUT",
                "-m", "comment", "--comment", FirewallRule.RULE_PREFIX + id, "-j", "ACCEPT");
        if (r.failed()) {
            CommandResult r2 = runner.run("iptables", "-D", "OUTPUT",
                    "-m", "comment", "--comment", FirewallRule.RULE_PREFIX + id, "-j", "ACCEPT");
            if (r2.failed()) {
                throw new NetworkException(NetworkException.Kind.COMMAND_FAILED,
                        "iptables rule could not be removed: " + r2.stderr());
            }
        }
        forget(id);
    }

    private void ensureElevated() throws NetworkException {
        if (!Elevation.isElevated()) {
            throw new NetworkException(NetworkException.Kind.PERMISSION_REQUIRED,
                    Elevation.requiredHint("modify iptables"));
        }
    }
}