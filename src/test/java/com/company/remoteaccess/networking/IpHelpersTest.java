package com.company.remoteaccess.networking;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IpHelpersTest {

    @Test
    void parseAndFormatRoundTrip() {
        assertEquals("192.168.1.10", IpHelpers.format(IpHelpers.parseIp("192.168.1.10")));
        assertEquals("10.50.0.4", IpHelpers.format(IpHelpers.parseIp("10.50.0.4")));
        assertEquals("0.0.0.0", IpHelpers.format(0L));
        assertEquals("255.255.255.255", IpHelpers.format(0xFFFFFFFFL));
    }

    @Test
    void rejectsInvalidIpv4() {
        assertThrows(IllegalArgumentException.class, () -> IpHelpers.parseIp("999.1.1.1"));
        assertThrows(IllegalArgumentException.class, () -> IpHelpers.parseIp("1.2.3"));
        assertThrows(IllegalArgumentException.class, () -> IpHelpers.parseIp("a.b.c.d"));
    }

    @Test
    void cidrMasks() {
        IpHelpers.Cidr c = IpHelpers.parseCidr("10.50.0.0/24");
        assertEquals(24, c.prefix());
        assertEquals("10.50.0.0", IpHelpers.format(c.network()));
        assertEquals("10.50.0.255", IpHelpers.format(c.broadcast()));
        assertEquals("255.255.255.0", IpHelpers.maskForPrefix(24));

        IpHelpers.Cidr small = IpHelpers.parseCidr("10.50.0.8/29");
        assertTrue(small.contains(IpHelpers.parseIp("10.50.0.14")));
        assertFalse(small.contains(IpHelpers.parseIp("10.50.0.16")));

        IpHelpers.Cidr zero = IpHelpers.parseCidr("0.0.0.0/0");
        assertTrue(zero.contains(IpHelpers.parseIp("8.8.8.8")));
    }

    @Test
    void nextHostAndLowestHost() {
        IpHelpers.Cidr c = IpHelpers.parseCidr("10.0.0.0/24");
        assertEquals("10.0.0.1", IpHelpers.lowestHost(c));
        assertEquals("10.0.0.1", IpHelpers.format(IpHelpers.nextHost(c.network())));
    }

    @Test
    void hostIndexing() {
        IpHelpers.Cidr c = IpHelpers.parseCidr("10.1.0.0/16");
        assertEquals("10.1.0.2", IpHelpers.host(c, 2));
        assertEquals("10.1.1.0", IpHelpers.host(c, 256));
    }

    @Test
    void isSubnetOf() {
        assertTrue(IpHelpers.isSubnetOf(
                IpHelpers.parseCidr("10.0.0.0/16"), IpHelpers.parseCidr("10.0.0.0/8")));
        assertFalse(IpHelpers.isSubnetOf(
                IpHelpers.parseCidr("10.0.0.0/8"), IpHelpers.parseCidr("10.0.0.0/16")));
    }

    @Test
    void overlaps() {
        assertTrue(IpHelpers.overlaps(
                IpHelpers.parseCidr("192.168.1.0/24"), IpHelpers.parseCidr("192.168.1.0/26")));
        assertFalse(IpHelpers.overlaps(
                IpHelpers.parseCidr("192.168.1.0/24"), IpHelpers.parseCidr("192.168.2.0/24")));
    }
}