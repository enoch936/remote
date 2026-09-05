package com.company.remoteaccess.networking;

/** Firewall rule model. Every rule carries an application identifier and purpose. */
public record FirewallRule(
        String id,
        String purpose,
        Protocol protocol,
        Integer localPort,
        Direction direction,
        Action action,
        String remoteCidr,
        String createdAt,
        String appVersion) {

    public enum Protocol { TCP, UDP, ICMP, ANY }

    public enum Direction { IN, OUT }

    public enum Action { ALLOW, BLOCK }

    public static final String RULE_PREFIX = "CompanyRemoteAccess::";

    public static Builder builder(String id, String purpose) {
        return new Builder(id, purpose);
    }

    public String displayName() {
        return RULE_PREFIX + id;
    }

    public static final class Builder {
        private final String id;
        private final String purpose;
        private Protocol protocol = Protocol.UDP;
        private Integer port;
        private Direction direction = Direction.IN;
        private Action action = Action.ALLOW;
        private String remoteCidr;
        private String createdAt;
        private String appVersion;

        private Builder(String id, String purpose) {
            this.id = id;
            this.purpose = purpose;
        }

        public Builder protocol(Protocol p) {
            this.protocol = p;
            return this;
        }

        public Builder port(int p) {
            this.port = p;
            return this;
        }

        public Builder direction(Direction d) {
            this.direction = d;
            return this;
        }

        public Builder action(Action a) {
            this.action = a;
            return this;
        }

        public Builder remoteCidr(String cidr) {
            this.remoteCidr = cidr;
            return this;
        }

        public Builder createdAt(String ts) {
            this.createdAt = ts;
            return this;
        }

        public Builder appVersion(String v) {
            this.appVersion = v;
            return this;
        }

        public FirewallRule build() {
            return new FirewallRule(id, purpose, protocol, port, direction, action,
                    remoteCidr,
                    createdAt == null ? java.time.Instant.now().toString() : createdAt,
                    appVersion == null ? "1.0.0" : appVersion);
        }
    }
}