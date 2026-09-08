package com.company.remoteaccess.diagnostics;

import com.company.remoteaccess.AppContext;
import com.company.remoteaccess.BuildInfo;
import com.company.remoteaccess.platform.Elevation;
import com.company.remoteaccess.platform.Os;
import com.company.remoteaccess.platform.RequirementChecker;
import com.company.remoteaccess.security.Secrets;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Static, redactable system snapshot used for support. Gathered headlessly via
 * {@code --diagnostics} or from the running app. Secret material (private keys,
 * tokens, pairing payloads) is stripped before the report is written or printed.
 */
public final class Diagnostics {

    private static final int LOG_TAIL = 40;

    private Diagnostics() {
    }

    /** Everything needed to render a report. */
    public record Report(
            String generatedAt,
            String appVersion,
            String javaVersion,
            String osFamily,
            String osArch,
            String osUser,
            String baseDir,
            boolean configPresent,
            boolean wgPresent,
            String wgPath,
            boolean elevated,
            String elevationHint,
            boolean online,
            int interfaceCount,
            boolean startupEnabled,
            String vpnBuildError,
            List<RequirementChecker.Requirement> requirements,
            List<String> recentLogLines) {

        /** Plain-text, line-oriented report suitable for a support ticket. */
        public String render() {
            StringBuilder sb = new StringBuilder();
            sb.append("Company Remote Access diagnostics\n");
            sb.append("---------------------------------\n");
            line(sb, "generated", generatedAt);
            line(sb, "app version", appVersion);
            line(sb, "java", javaVersion);
            line(sb, "os", osFamily + " / " + osArch);
            line(sb, "user", osUser);
            line(sb, "data directory", baseDir);
            line(sb, "configuration", configPresent ? "present" : "missing");
            line(sb, "wireguard", wgPresent ? "found (" + wgPath + ")" : "not found");
            line(sb, "elevated", String.valueOf(elevated));
            line(sb, "elevation hint", elevationHint);
            line(sb, "network online", String.valueOf(online));
            line(sb, "interfaces", String.valueOf(interfaceCount));
            line(sb, "start with OS", String.valueOf(startupEnabled));
            line(sb, "vpn engine error", vpnBuildError == null || vpnBuildError.isBlank() ? "none" : vpnBuildError);
            if (!requirements.isEmpty()) {
                sb.append("requirements\n");
                for (RequirementChecker.Requirement r : requirements) {
                    sb.append("  - ").append(r.label()).append(": ")
                            .append(r.status()).append(" - ").append(r.detail()).append('\n');
                }
            }
            sb.append("recent log lines (").append(recentLogLines.size()).append(" entries, redacted)\n");
            for (String l : recentLogLines) {
                sb.append("  ").append(l).append('\n');
            }
            return sb.toString();
        }

        private static void line(StringBuilder sb, String key, String value) {
            sb.append(key).append(": ").append(value == null ? "" : value).append('\n');
        }
    }

    /** Gather a report from the current process. */
    public static Report gather(AppContext ctx, boolean online, List<RequirementChecker.Requirement> requirements,
                                boolean startupEnabled) {
        boolean wgPresent = false;
        String wgPath = "";
        for (RequirementChecker.Requirement r : requirements) {
            if ("wg".equals(r.id()) && r.status() == RequirementChecker.Status.OK) {
                wgPresent = true;
                String d = r.detail() == null ? "" : r.detail();
                if (d.startsWith("found")) {
                    wgPath = d.contains("(") && d.endsWith(")") ? d : "";
                }
            }
        }
        return new Report(
                LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
                BuildInfo.version(),
                System.getProperty("java.version", "unknown"),
                Os.family().name(),
                System.getProperty("os.arch", "unknown"),
                System.getProperty("user.name", "unknown"),
                ctx.baseDir.toAbsolutePath().toString(),
                ctx.configManager.exists(),
                wgPresent,
                wgPath,
                Elevation.isElevated(),
                Elevation.requiredHint("manage the VPN"),
                online,
                ctx.network == null ? 0 : safeInterfaces(ctx),
                startupEnabled,
                ctx.vpnBuildError() == null ? null : ctx.vpnBuildError().getMessage(),
                requirements,
                tailLog(ctx.logsDir.resolve("app.log")));
    }

    private static int safeInterfaces(AppContext ctx) {
        try {
            return ctx.network.snapshot().interfaces().size();
        } catch (RuntimeException e) {
            return 0;
        }
    }

    /** Last {@value LOG_TAIL} lines of the app log. */
    static List<String> tailLog(Path logFile) {
        try {
            List<String> all = Files.readAllLines(logFile);
            int from = Math.max(0, all.size() - LOG_TAIL);
            return all.subList(from, all.size());
        } catch (IOException e) {
            return List.of("(log file unavailable: " + e.getMessage() + ")");
        }
    }

    /** Write a redacted report and return the rendered text. */
    public static String write(Path out, Report report) throws IOException {
        String rendered = Secrets.redact(report.render());
        Files.writeString(out, rendered);
        return rendered;
    }
}