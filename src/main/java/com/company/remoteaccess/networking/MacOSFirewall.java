package com.company.remoteaccess.networking;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.platform.CommandRunner;

import java.nio.file.Path;

/**
 * macOS firewall adapter.
 *
 * <p>The macOS Application Firewall is off-by-default and, when turned on, prompts
 * per application for inbound connections; WireGuard-side inbound UDP is therefore
 * permitted by default OS behaviour. No pf rule is injected (reloading the whole
 * pf ruleset could disable the user's own firewall). We still record the rule so the
 * manifest stays truthful and {@link #removeAllManaged()} bookkeeping is consistent.
 */
public final class MacOSFirewall extends FirewallManager {

    MacOSFirewall(CommandRunner runner, Path manifestPath) {
        super(runner, manifestPath);
    }

    @Override
    public void applyRule(FirewallRule rule) throws NetworkException {
        record(rule);
        AppLogger.getLogger().info(LogCategory.FIREWALL,
                "macOS permits inbound %s on port %s by default; no pf rule injected",
                rule.protocol(), rule.localPort() == null ? "-" : rule.localPort());
    }

    @Override
    public void removeRuleById(String id) throws NetworkException {
        forget(id);
        AppLogger.getLogger().info(LogCategory.FIREWALL, "macOS firewall bookkeeping for %s cleared", id);
    }
}