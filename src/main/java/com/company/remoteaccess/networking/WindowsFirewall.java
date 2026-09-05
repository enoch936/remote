package com.company.remoteaccess.networking;

import com.company.remoteaccess.platform.CommandResult;
import com.company.remoteaccess.platform.CommandRunner;
import com.company.remoteaccess.platform.Elevation;

import java.nio.file.Path;

/** Windows firewall adapter (netsh advfirewall). Requires administrator rights. */
public final class WindowsFirewall extends FirewallManager {

    WindowsFirewall(CommandRunner runner, Path manifestPath) {
        super(runner, manifestPath);
    }

    @Override
    public void applyRule(FirewallRule rule) throws NetworkException {
        ensureElevated();
        String name = rule.displayName();
        String dir = rule.direction() == FirewallRule.Direction.IN ? "in" : "out";
        String action = rule.action() == FirewallRule.Action.ALLOW ? "allow" : "block";
        String proto = rule.protocol() == FirewallRule.Protocol.ANY ? "any" : rule.protocol().name();
        String localPort = rule.localPort() == null ? "any" : String.valueOf(rule.localPort());
        String remote = rule.remoteCidr() == null || rule.remoteCidr().isBlank()
                ? "any" : rule.remoteCidr();

        CommandResult r = runner.run("netsh", "advfirewall", "firewall", "add", "rule",
                "name=" + name,
                "dir=" + dir,
                "action=" + action,
                "protocol=" + proto,
                "localport=" + localPort,
                "remoteip=" + remote,
                "profile=any");
        if (r.failed()) {
            throw new NetworkException(NetworkException.Kind.COMMAND_FAILED,
                    "firewall rule could not be added: " + r.stderr());
        }
        record(rule);
    }

    @Override
    public void removeRuleById(String id) throws NetworkException {
        ensureElevated();
        CommandResult r = runner.run("netsh", "advfirewall", "firewall", "delete", "rule",
                "name=" + FirewallRule.RULE_PREFIX + id);
        if (r.failed()) {
            throw new NetworkException(NetworkException.Kind.COMMAND_FAILED,
                    "firewall rule could not be removed: " + r.stderr());
        }
        forget(id);
    }

    private void ensureElevated() throws NetworkException {
        if (!Elevation.isElevated()) {
            throw new NetworkException(NetworkException.Kind.PERMISSION_REQUIRED,
                    Elevation.requiredHint("modify the Windows firewall"));
        }
    }
}