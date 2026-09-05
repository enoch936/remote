package com.company.remoteaccess.vpn;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WgConfigBuilderTest {

    private static final String PRIV = "yOOvprivatekeytesttesttesttesttesttes+t=".replace("+", "A").replace("/", "a");
    private static final String PUB = "PUBK-testkeytestkeytestkeytestkeytestkeyxz";

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
    void requiresAtLeastOnePeer() {
        assertThrows(IllegalStateException.class,
                () -> new WgConfigBuilder().interfaceKeys(PRIV, "10.50.0.2/32").build());
    }
}