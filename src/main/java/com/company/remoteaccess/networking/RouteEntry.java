package com.company.remoteaccess.networking;

/** A route entry on the local routing table. */
public record RouteEntry(String network, int prefix, String gateway,
                         String interfaceName, int metric, boolean isDefault,
                         boolean managedByApp) {

    public boolean isDefault() {
        return isDefault || ("0.0.0.0".equals(network) && prefix == 0);
    }

    public String cidr() {
        return network + "/" + prefix;
    }
}