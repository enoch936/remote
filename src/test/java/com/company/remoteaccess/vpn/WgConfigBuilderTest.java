package com.company.remoteaccess.vpn;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WgConfigBuilderTest {

    private static final String PRIV = "A".repeat(43) + "=";
    private static final String PUB = "B".repeat(43) + "=";

    @Test
    void buildsInterfaceAndPeerSections() {
        String conf = new WgConfigBuilder()
                .interfaceKeys(PRIV, "10.50.0.2/32")
                .dns("10.50.0.1")
                .mtu(1420)
                .listenPort(51820)
                .addPeer(PUB, "10.50.0.0/24", "gw.example.com:51820", 25)
                .build();
        assertTrue(conf.contains("[Interface]"));
        assertTrue(conf.contains("PrivateKey = " + PRIV));
        assertTrue(conf.contains("Address = 10.50.0.2/32"));
        assertTrue(conf.contains("ListenPort = 51820"));
        assertTrue(conf.contains("MTU = 1420"));
        assertTrue(conf.contains("[Peer]"));
        assertTrue(conf.contains("PublicKey = " + PUB));
        assertTrue(conf.contains("AllowedIPs = 10.50.0.0/24"));
        assertTrue(conf.contains("Endpoint = gw.example.com:51820"));
        assertTrue(conf.contains("PersistentKeepalive = 25"));
    }

    @Test
    void omitsOptionalKeysWhenNull() {
        String conf = new WgConfigBuilder()
                .interfaceKeys(PRIV, "10.50.0.2/32")
                .addPeer(PUB, "10.50.0.0/24", null, null)
                .build();
        assertTrue(!conf.contains("Endpoint"));
        assertTrue(!conf.contains("PersistentKeepalive"));
        assertTrue(!conf.contains("DNS"));
    }

    @Test
    void requiresPrivateKeyAndAddress() {
        assertThrows(IllegalStateException.class,
                () -> new WgConfigBuilder().addPeer(PUB, "10.0.0.0/24", null, null).build());
        assertThrows(IllegalStateException.class,
                () -> new WgConfigBuilder().interfaceKeys(null, "10.0.0.2/32")
                        .addPeer(PUB, "10.0.0.0/24", null, null).build());
    }

    @Test
    void allowsEmptyPeerList() {
        String conf = new WgConfigBuilder()
                .interfaceKeys(PRIV, "10.50.0.1/24")
                .listenPort(51820)
                .build();
        assertTrue(conf.contains("[Interface]"));
        assertTrue(conf.contains("PrivateKey = " + PRIV));
        assertTrue(conf.contains("ListenPort = 51820"));
        assertTrue(!conf.contains("[Peer]"));
    }

    @Test
    void rejectsMalformedInterfacePrivateKey() {
        assertThrows(IllegalArgumentException.class,
                () -> new WgConfigBuilder().interfaceKeys("not-a-wg-key", "10.50.0.1/24").build());
    }

    @Test
    void rejectsMalformedPeerPublicKey() {
        WgConfigBuilder wg = new WgConfigBuilder()
                .interfaceKeys(PRIV, "10.50.0.1/24")
                .addPeer("PUBK-testkeytestkeytestkeytestkeytestkeyxz", "10.50.0.2/32", null, null);
        assertThrows(IllegalArgumentException.class, wg::build);
    }

    @Test
    void rejectsMalformedPeerEndpoint() {
        WgConfigBuilder wg = new WgConfigBuilder()
                .interfaceKeys(PRIV, "10.50.0.1/24")
                .addPeer(PUB, "10.50.0.2/32", "bad endpoint with spaces:51820", 25);
        assertThrows(IllegalArgumentException.class, wg::build);
    }

    @Test
    void rejectsMalformedAllowedIps() {
        WgConfigBuilder wg = new WgConfigBuilder()
                .interfaceKeys(PRIV, "10.50.0.1/24")
                .addPeer(PUB, "10.50.0.2/32,999.1.1.1/32", null, null);
        assertThrows(IllegalArgumentException.class, wg::build);
    }

    @Test
    void rejectsMalformedInterfaceAddress() {
        WgConfigBuilder wg = new WgConfigBuilder()
                .interfaceKeys(PRIV, "10.50.0.1")
                .addPeer(PUB, "10.50.0.2/32", null, null);
        assertThrows(IllegalArgumentException.class, wg::build);
    }
}