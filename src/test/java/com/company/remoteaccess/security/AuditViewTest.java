package com.company.remoteaccess.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditViewTest {

    @TempDir
    Path tmp;

    @Test
    void readsAndRendersEntriesNewestFirst() throws Exception {
        Path file = tmp.resolve("audit.log");
        AuditLog log = new AuditLog(file);
        log.append("admin", "device_added", "device=laptop address=10.50.0.2");
        log.append("admin", "device_blocked", "device=laptop");

        var entries = AuditView.read(file, 50);
        assertEquals(2, entries.size());
        assertEquals("admin", entries.get(0).actor());
        assertEquals("device_added", entries.get(0).action());
        assertTrue(entries.get(0).detailHash().length() >= 12, "detail hash shown, never raw details");

        String rendered = AuditView.render(entries);
        assertTrue(rendered.indexOf("device_blocked") < rendered.indexOf("device_added"));
        assertTrue(!rendered.contains("10.50.0.2"), "details stay hashed in the viewer");
    }

    @Test
    void verifyReflectsChainIntegrity() {
        Path file = tmp.resolve("audit.log");
        assertTrue(AuditView.verified(file));
        new AuditLog(file).append("admin", "device_added", "details");
        assertTrue(AuditView.verified(file));
    }

    @Test
    void missingFileReadsEmpty() {
        assertTrue(AuditView.read(tmp.resolve("nope.log"), 10).isEmpty());
        assertTrue(AuditView.verified(tmp.resolve("nope.log")));
    }
}