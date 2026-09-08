package com.company.remoteaccess.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ValidationTest {

    private static final String GOOD_KEY = "A".repeat(43) + "=";

    @Test
    void acceptsRealWireGuardKeyFormat() {
        assertTrue(Validation.isWireGuardKey(GOOD_KEY));
        assertTrue(Validation.isWireGuardKey("8b9ZqNxVX6Y0rW3kTc8e1oQ7gP2hA4sD5fJ9mB6nC3v="));
    }

    @Test
    void rejectsBadWireGuardKeys() {
        assertFalse(Validation.isWireGuardKey(null));
        assertFalse(Validation.isWireGuardKey(""));
        assertFalse(Validation.isWireGuardKey("short"));
        assertFalse(Validation.isWireGuardKey("A".repeat(43))); // no '='
        assertFalse(Validation.isWireGuardKey("A".repeat(44) + "=")); // too long
        assertFalse(Validation.isWireGuardKey("A".repeat(42) + "$=")); // bad alphabet
        assertFalse(Validation.isWireGuardKey("a\n" + "A".repeat(41) + "=")); // control char
    }

    @Test
    void acceptsValidEndpoints() {
        assertTrue(Validation.isValidEndpoint("gw.example.com:51820"));
        assertTrue(Validation.isValidEndpoint("gw.example.com"));
        assertTrue(Validation.isValidEndpoint("203.0.113.10:51820"));
        assertTrue(Validation.isValidEndpoint("203.0.113.10"));
        assertTrue(Validation.isValidEndpoint("vpn.company.local."));
    }

    @Test
    void rejectsInvalidEndpoints() {
        assertFalse(Validation.isValidEndpoint(null));
        assertFalse(Validation.isValidEndpoint(""));
        assertFalse(Validation.isValidEndpoint("host with space:51820"));
        assertFalse(Validation.isValidEndpoint("gw.example.com:0"));
        assertFalse(Validation.isValidEndpoint("gw.example.com:65536"));
        assertFalse(Validation.isValidEndpoint("gw.example.com:port"));
        assertFalse(Validation.isValidEndpoint("gw.example.com:51820:extra"));
        assertFalse(Validation.isValidEndpoint("-bad.example.com:51820"));
        assertFalse(Validation.isValidEndpoint("999.1.1.1:51820"));
        assertFalse(Validation.isValidEndpoint("bad..example.com"));
        assertFalse(Validation.isValidEndpoint("bad host"));
    }

    @Test
    void requireEndpointThrowsWithField() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> Validation.requireEndpoint("not an endpoint", "gateway endpoint"));
        assertTrue(ex.getMessage().contains("gateway endpoint"));
    }

    @Test
    void deviceNameRules() {
        assertTrue(Validation.isValidDeviceName("John's Laptop-2"));
        assertTrue(Validation.isValidDeviceName("john-laptop"));
        assertFalse(Validation.isValidDeviceName(null));
        assertFalse(Validation.isValidDeviceName("  "));
        assertFalse(Validation.isValidDeviceName("name/with/slashes"));
        assertFalse(Validation.isValidDeviceName("name;with;semicolon"));
        assertFalse(Validation.isValidDeviceName("name\nnewline"));
        assertFalse(Validation.isValidDeviceName("A".repeat(65)));
    }

    @Test
    void dnsListRules() {
        assertTrue(Validation.isValidDnsList("1.1.1.1,8.8.8.8"));
        assertTrue(Validation.isValidDnsList("10.50.0.1"));
        assertFalse(Validation.isValidDnsList("localhost"));
        assertFalse(Validation.isValidDnsList("1.1.1.1,999.1.1.1"));
        assertFalse(Validation.isValidDnsList("1.1.1.1;evil\n"));
    }

    @Test
    void requirePortRejectsOutOfRange() {
        assertThrows(IllegalArgumentException.class, () -> Validation.requirePort(0, "listen port"));
        assertThrows(IllegalArgumentException.class, () -> Validation.requirePort(65536, "listen port"));
    }
}