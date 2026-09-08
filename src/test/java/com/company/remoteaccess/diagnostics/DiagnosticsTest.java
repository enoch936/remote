package com.company.remoteaccess.diagnostics;

import com.company.remoteaccess.platform.RequirementChecker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DiagnosticsTest {

    @TempDir
    Path tmp;

    private static Diagnostics.Report report() {
        return new Diagnostics.Report(
                "2026-09-06T12:00:00",
                "1.0.0",
                "21.0.12",
                "WINDOWS",
                "amd64",
                "operator",
                "C:\\data",
                true,
                true,
                "C:\\Program Files\\WireGuard\\wg.exe",
                false,
                "Restart the application as Administrator.",
                true,
                3,
                true,
                null,
                List.of(new RequirementChecker.Requirement("wg", "WireGuard tooling",
                        RequirementChecker.Status.OK, "found")),
                List.of("line one", "line two"));
    }

    @Test
    void renderContainsAllSections() {
        String text = report().render();
        assertTrue(text.contains("Company Remote Access diagnostics"));
        assertTrue(text.contains("generated: 2026-09-06T12:00:00"));
        assertTrue(text.contains("app version: 1.0.0"));
        assertTrue(text.contains("data directory: C:\\data"));
        assertTrue(text.contains("wireguard: found"));
        assertTrue(text.contains("requirements"));
        assertTrue(text.contains("recent log lines (2 entries, redacted)"));
        assertTrue(text.contains("line two"));
    }

    @Test
    void writeRedactsSecrets() throws Exception {
        String key = "F".repeat(43) + "=";
        Diagnostics.Report r = report();
        r = new Diagnostics.Report(r.generatedAt(), r.appVersion(), r.javaVersion(),
                r.osFamily(), r.osArch(), r.osUser(), r.baseDir(), r.configPresent(),
                r.wgPresent(), r.wgPath(), r.elevated(), r.elevationHint(),
                r.online(), r.interfaceCount(), r.startupEnabled(), r.vpnBuildError(),
                r.requirements(),
                List.of("PrivateKey = " + key, "handshake ok with " + key));

        Path out = tmp.resolve("report.txt");
        String rendered = Diagnostics.write(out, r);

        assertTrue(Files.exists(out));
        assertTrue(Files.readString(out).contains("[REDACTED]"));
        assertTrue(rendered.contains("[REDACTED]"), rendered);
        assertFalse(rendered.contains(key), "raw key leaked into report");
    }

    @Test
    void tailLogReturnsLastLines() throws Exception {
        Path log = tmp.resolve("app.log");
        List<String> lines = new ArrayList<>();
        for (int i = 1; i <= 50; i++) {
            lines.add("entry " + i);
        }
        Files.write(log, lines);

        List<String> tail = Diagnostics.tailLog(log);
        assertEquals(40, tail.size());
        assertEquals("entry 11", tail.get(0));
        assertEquals("entry 50", tail.get(39));
    }

    @Test
    void tailLogMissingFileIsHandled() {
        List<String> tail = Diagnostics.tailLog(tmp.resolve("nope.log"));
        assertEquals(1, tail.size());
        assertTrue(tail.get(0).contains("unavailable"));
    }

    @Test
    void vpnErrorIsRenderedExactlyOnce() {
        Diagnostics.Report r = new Diagnostics.Report(
                "now", "1.0.0", "21", "WINDOWS", "amd64", "u", "C:\\d",
                false, false, "", false, "hint", false, 0, false,
                "wg binary missing", List.of(), List.of());
        String text = r.render();
        assertTrue(text.contains("vpn engine error: wg binary missing"));
        assertNotEquals(-1, text.indexOf("wg binary missing"));
        assertEquals(text.lastIndexOf("wg binary missing"), text.indexOf("wg binary missing"));
    }
}