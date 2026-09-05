package com.company.remoteaccess.networking;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** IPv4/CIDR math used across routing, firewall and validation. */
public final class IpHelpers {

    public record Cidr(long network, int prefix) {
        public long mask() {
            return prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        }

        public long broadcast() {
            return network | (~mask() & 0xFFFFFFFFL);
        }

        public String networkString() {
            return format(network) + "/" + prefix;
        }

        public boolean contains(long ip) {
            return (ip & mask()) == (network & mask());
        }
    }

    private IpHelpers() {
    }

    private static final Pattern CIDR_PATTERN =
            Pattern.compile("^(\\d{1,3}(?:\\.\\d{1,3}){3})/(\\d{1,2})$");

    public static long parseIp(String ip) {
        Matcher m = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$").matcher(ip.trim());
        if (!m.matches()) {
            throw new IllegalArgumentException("invalid IPv4: " + ip);
        }
        long result = 0;
        for (int i = 1; i <= 4; i++) {
            int octet = Integer.parseInt(m.group(i));
            if (octet > 255) {
                throw new IllegalArgumentException("invalid IPv4: " + ip);
            }
            result = (result << 8) | octet;
        }
        return result;
    }

    public static String format(long ip) {
        return ((ip >> 24) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "."
                + ((ip >> 8) & 0xFF) + "." + (ip & 0xFF);
    }

    public static Cidr parseCidr(String cidr) {
        Matcher m = CIDR_PATTERN.matcher(cidr.trim());
        if (!m.matches()) {
            throw new IllegalArgumentException("invalid CIDR: " + cidr);
        }
        int prefix = Integer.parseInt(m.group(2));
        if (prefix > 32) {
            throw new IllegalArgumentException("invalid prefix: " + cidr);
        }
        long ip = parseIp(m.group(1));
        long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        return new Cidr(ip & mask, prefix);
    }

    public static String maskForPrefix(int prefix) {
        if (prefix < 0 || prefix > 32) {
            throw new IllegalArgumentException("prefix out of range: " + prefix);
        }
        return format(prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL);
    }

    public static long nextHost(long network) {
        return (network + 1) & 0xFFFFFFFFL;
    }

    /** Host numbered {@code index} inside the CIDR (index 0 is the network address). */
    public static String host(Cidr cidr, long index) {
        return format((cidr.network() + index) & 0xFFFFFFFFL);
    }

    public static String lowestHost(Cidr cidr) {
        return format(nextHost(cidr.network()));
    }

    /** True when {@code a} is strictly contained in {@code b}. */
    public static boolean isSubnetOf(Cidr a, Cidr b) {
        return a.prefix() >= b.prefix() && b.contains(a.network());
    }

    public static boolean overlaps(Cidr a, Cidr b) {
        return a.contains(b.network()) || b.contains(a.network());
    }
}