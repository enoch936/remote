package com.company.remoteaccess.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditLogTest {

    @TempDir
    Path tmp;

    @Test
    void appendsChainedLinesAndVerifies() throws Exception {
        Path file = tmp.resolve("audit.log");
        AuditLog log = new AuditLog(file);
        log.append("registry", "device_added", "device=laptop address=10.50.0.2");
        log.append("pairing", "token_issued", "device=laptop");
        log.append("gateway", "state_online", "from=starting");

        List<String> lines = Files.readAllLines(file);
        assertEquals(3, lines.size());
        for (String line : lines) {
            assertEquals(5, line.split("\\s*\\|\\s*", -1).length);
        }
        assertTrue(log.verifyChain());
    }

    @Test
    void tamperedLineBreaksChain() throws Exception {
        Path file = tmp.resolve("audit.log");
        AuditLog log = new AuditLog(file);
        log.append("registry", "device_added", "device=laptop");
        log.append("registry", "device_revoked", "device=laptop");

        List<String> lines = Files.readAllLines(file);
        String tampered = lines.get(0).replace("device_added", "device_ADMITTED");
        Files.writeString(file, String.join(System.lineSeparator(), tampered, lines.get(1)),
                StandardCharsets.UTF_8);

        assertFalse(AuditLog.verifyChain(file));
    }

    @Test
    void wireGuardKeysAreRedactedBeforeHashing() throws Exception {
        String key = "A".repeat(43) + "=";
        Path file = tmp.resolve("audit.log");
        AuditLog log = new AuditLog(file);
        log.append("pairing", "token_issued", "device=laptop bound_key=" + key);

        String content = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
        assertFalse(content.contains(key), "raw key must never appear in the audit file");
        // only the SHA-256 of the redacted detail text is stored, never the text
        String stored = content.split("\\s*\\|\\s*")[3];
        assertEquals(Secrets.hash256(Secrets.redact("device=laptop bound_key=" + key)), stored);
        assertTrue(log.verifyChain());
    }

    @Test
    void blankActorOrActionIsSkipped() throws Exception {
        Path file = tmp.resolve("audit.log");
        AuditLog log = new AuditLog(file);
        log.append("", "action", "details");
        log.append("actor", "", "details");
        log.append(null, "action", "details");
        log.append("actor", "ok", "details");

        assertEquals(1, Files.readAllLines(file).size());
        assertTrue(log.verifyChain());
    }

    @Test
    void tailReturnsMostRecentEntries() {
        Path file = tmp.resolve("audit.log");
        AuditLog log = new AuditLog(file);
        for (int i = 0; i < 5; i++) {
            log.append("actor", "step" + i, "n=" + i);
        }
        List<String> tail = log.tail(2);
        assertEquals(2, tail.size());
        assertTrue(tail.get(0).contains("step3"));
        assertTrue(tail.get(1).contains("step4"));
        assertEquals(5, log.tail(100).size());
        assertEquals(0, log.tail(0).size());
    }

    @Test
    void missingFileVerifiesAndTailsEmpty() {
        Path missing = tmp.resolve("does-not-exist.log");
        AuditLog log = new AuditLog(missing);
        assertTrue(log.verifyChain());
        assertTrue(log.tail(10).isEmpty());
    }
}