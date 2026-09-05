package com.company.remoteaccess.platform;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Runs external platform tooling (route, netsh, ip, wg, powershell, ...) with a
 * timeout and captures stdout/stderr. All networking and VPN control goes through
 * this class so it can be faked easily in tests.
 */
public class CommandRunner {

    public static final long DEFAULT_TIMEOUT_SECONDS = 45;

    private final List<String> globalPrefix = new java.util.ArrayList<>();

    public CommandRunner() {
    }

    public CommandRunner withPrefix(List<String> prefix) {
        this.globalPrefix.addAll(prefix);
        return this;
    }

    public CommandResult run(String... command) {
        return run(java.util.Arrays.asList(command), DEFAULT_TIMEOUT_SECONDS);
    }

    public CommandResult run(List<String> command) {
        return run(command, DEFAULT_TIMEOUT_SECONDS);
    }

    public CommandResult run(List<String> command, long timeoutSeconds) {
        return run(command, null, timeoutSeconds);
    }

    /** Run a command, optionally feeding {@code stdinData} to its standard input. */
    public CommandResult runWithInput(List<String> command, String stdinData, long timeoutSeconds) {
        return run(command, stdinData, timeoutSeconds);
    }

    private CommandResult run(List<String> command, String stdinData, long timeoutSeconds) {
        List<String> full = new java.util.ArrayList<>(globalPrefix);
        full.addAll(command);
        String joined = String.join(" ", full.stream()
                .map(s -> s.contains(" ") ? "\"" + s + "\"" : s)
                .toList());
        AppLogger.getLogger().debug(LogCategory.SYSTEM, "exec: %s", joined);

        ProcessBuilder pb = new ProcessBuilder(full);
        pb.redirectErrorStream(false);
        String out;
        String err;
        int code;
        try {
            Process p = pb.start();
            if (stdinData != null) {
                try (var w = p.getOutputStream()) {
                    w.write(stdinData.getBytes(StandardCharsets.UTF_8));
                }
            }
            // read streams concurrently to avoid deadlock on full pipes
            var outReader = new java.util.concurrent.CompletableFuture<String>();
            var errReader = new java.util.concurrent.CompletableFuture<String>();
            Thread ot = new Thread(() -> outReader.complete(readStream(p.getInputStream())), "cmd-out");
            ot.setDaemon(true);
            Thread et = new Thread(() -> errReader.complete(readStream(p.getErrorStream())), "cmd-err");
            et.setDaemon(true);
            ot.start();
            et.start();
            boolean finished = p.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!finished) {
                p.destroyForcibly();
                AppLogger.getLogger().warn(LogCategory.SYSTEM, "command timed out: %s", joined);
                return new CommandResult(124, "", "timeout after " + timeoutSeconds + "s");
            }
            code = p.exitValue();
            out = outReader.get(5, TimeUnit.SECONDS);
            err = errReader.get(5, TimeUnit.SECONDS);
        } catch (IOException e) {
            AppLogger.getLogger().warn(LogCategory.SYSTEM,
                    "unable to execute '%s': %s", joined, e.getMessage());
            return new CommandResult(127, "", e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new CommandResult(130, "", "interrupted");
        } catch (Exception e) {
            return new CommandResult(1, "", e.getMessage());
        }
        if (code != 0 && !err.isBlank()) {
            AppLogger.getLogger().debug(LogCategory.SYSTEM, "stderr: %s", err.trim());
        }
        return new CommandResult(code, out, err);
    }

    private static String readStream(java.io.InputStream stream) {
        try {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "";
        }
    }
}