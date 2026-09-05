package com.company.remoteaccess.networking;

import java.util.List;

/** A detected network interface. */
public record NetInterface(
        int index,
        String name,
        Type type,
        boolean up,
        String mac,
        List<String> ipv4Addresses,
        long linkSpeedMbpsLow) {

    public enum Type { ETHERNET, WIFI, VPN, LOOPBACK, OTHER }

    public boolean hasIpv4() {
        return ipv4Addresses != null && !ipv4Addresses.isEmpty();
    }

    public String firstIpv4() {
        return ipv4Addresses == null || ipv4Addresses.isEmpty() ? null : ipv4Addresses.get(0);
    }

    public String displayName() {
        if (name == null || name.isBlank()) {
            return "(unnamed)";
        }
        return name;
    }
}