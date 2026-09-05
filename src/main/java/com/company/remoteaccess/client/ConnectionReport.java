package com.company.remoteaccess.client;

/** Result of one connection-health check (spec section 28). */
public record ConnectionReport(java.util.List<Check> checks) {

    public record Check(String name, boolean ok, String detail, long latencyMs) {
        public Check {
            detail = detail == null ? "" : detail;
        }
    }

    public boolean allOk() {
        return checks.stream().allMatch(Check::ok);
    }

    public boolean anyFailed() {
        return !allOk();
    }
}