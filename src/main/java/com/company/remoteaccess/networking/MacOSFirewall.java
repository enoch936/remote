package com.company.remoteaccess.networking;

import com.company.remoteaccess.platform.CommandRunner;

import java.nio.file.Path;

/**
 * macOS adapter (optional). Uses {@code /usr/libexec/ApplicationFirewall/socketfilterfw}
 * which requires root and is only invoked with explicit administrator consent.
 */
public final class MacOSFirewall extends FirewallManager {

    MacOSFirewall(CommandRunner runner, Path manifestPath) {
        super(runner, manifestPath);
    }

    @Override
    public void applyRule(FirewallRule rule) throws NetworkException {
        throw new NetworkException(NetworkException.Kind.UNSUPPORTED_PLATFORM,
                "macOS firewall automation requires manual administrator configuration: " + rule.purpose());
    }

    @Override
    public void removeRuleById(String id) throws NetworkException {
        throw new NetworkException(NetworkException.Kind.UNSUPPORTED_PLATFORM,
                "macOS firewall automation requires manual administrator configuration");
    }
}