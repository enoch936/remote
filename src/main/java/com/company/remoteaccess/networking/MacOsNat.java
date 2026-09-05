package com.company.remoteaccess.networking;

import com.company.remoteaccess.platform.CommandRunner;

import java.util.List;

/** macOS NAT adapter (optional): reports explicit administrator actions. */
public final class MacOsNat extends NatManager {

    MacOsNat(CommandRunner runner) {
        super(runner);
    }

    @Override
    public void enableNat(String vpnSubnetCidr, String lanInterface, String lanCidr)
            throws NetworkException {
        throw new NetworkException(NetworkException.Kind.UNSUPPORTED_PLATFORM,
                "NAT automation on macOS requires manual configuration of pf rules. "
                        + "See Settings > Network for the exact pf rule to add.");
    }

    @Override
    public void disableNat(String vpnSubnetCidr, String lanInterface, String lanCidr)
            throws NetworkException {
        // nothing was automated; nothing to remove
    }

    @Override
    public boolean isEnabled() {
        return false;
    }

    @Override
    public List<String> missingRequirements(String vpnSubnetCidr, String lanInterface) {
        return List.of("On macOS, configure pf-based NAT manually with administrator rights.");
    }
}