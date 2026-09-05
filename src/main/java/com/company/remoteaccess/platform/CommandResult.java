package com.company.remoteaccess.platform;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Result of an executed external command. */
public record CommandResult(int exitCode, String stdout, String stderr) {

    public boolean success() {
        return exitCode == 0;
    }

    public boolean failed() {
        return exitCode != 0;
    }

    public List<String> lines() {
        if (stdout == null || stdout.isBlank()) {
            return List.of();
        }
        return new ArrayList<>(Arrays.asList(stdout.split("\\r?\\n")));
    }

    @Override
    public String toString() {
        return String.format("exit=%d stdout=[%s] stderr=[%s]",
                exitCode, truncate(stdout), truncate(stderr));
    }

    private static String truncate(String s) {
        if (s == null) {
            return "";
        }
        return s.length() > 4000 ? s.substring(0, 4000) + "…" : s;
    }
}