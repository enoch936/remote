package com.company.remoteaccess.core.authentication;

/** Identity of an authorized client device. */
public record ClientIdentity(String deviceName, String publicKey, String vpnAddress) {

    public ClientIdentity {
        if (publicKey == null || publicKey.isBlank()) {
            throw new IllegalArgumentException("publicKey must not be blank");
        }
        if (deviceName == null || deviceName.isBlank()) {
            deviceName = "device-" + publicKey.substring(0, Math.min(8, publicKey.length()));
        }
    }
}