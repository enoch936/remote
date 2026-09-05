package com.company.remoteaccess.server;

import java.time.Instant;

/**
 * An authorized client device as tracked by the gateway. Persisted in the
 * client registry.
 */
public final class ServerPeer {

    public enum Status { AUTHORIZED, REVOKED, BLOCKED }

    public final String deviceName;
    public final String publicKey;
    public final String vpnAddress;
    public final Status status;
    public final String addedAt;
    public final String lastSeenAt;
    public final String note;

    public ServerPeer(String deviceName, String publicKey, String vpnAddress,
                      Status status, String addedAt, String lastSeenAt, String note) {
        this.deviceName = deviceName;
        this.publicKey = publicKey;
        this.vpnAddress = vpnAddress;
        this.status = status == null ? Status.AUTHORIZED : status;
        this.addedAt = addedAt == null ? Instant.now().toString() : addedAt;
        this.lastSeenAt = lastSeenAt;
        this.note = note;
    }

    public ServerPeer withLastSeen(String lastSeen) {
        return new ServerPeer(deviceName, publicKey, vpnAddress, status, addedAt, lastSeen, note);
    }

    public ServerPeer withStatus(Status s) {
        return new ServerPeer(deviceName, publicKey, vpnAddress, s, addedAt, lastSeenAt, note);
    }

    public ServerPeer renamed(String newName) {
        return new ServerPeer(newName, publicKey, vpnAddress, status, addedAt, lastSeenAt, note);
    }
}