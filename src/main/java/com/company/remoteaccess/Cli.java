package com.company.remoteaccess;

import java.nio.file.Path;

/**
 * Headless command-line entry points (all before JavaFX starts):
 *
 * <pre>
 *   --version                         print the app version, exit
 *   --diagnostics [out.txt]           write a redacted support report, exit
 *   --data-dir &lt;dir&gt;                  use an explicit data directory
 * </pre>
 */
public final class Cli {

    public enum Action { LAUNCH, VERSION, DIAGNOSTICS }

    public record Result(Action action, Path diagnosticsFile, Path dataDir) {

        public static Result launch(Path dataDir) {
            return new Result(Action.LAUNCH, null, dataDir);
        }
    }

    private Cli() {
    }

    private static final String VERSION = "--version";
    private static final String DIAGNOSTICS = "--diagnostics";
    private static final String DATA_DIR = "--data-dir";

    public static Result parse(String[] args) {
        if (args == null) {
            return Result.launch(null);
        }
        Path dataDir = null;
        Path diagFile = null;
        boolean diagnostics = false;
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case VERSION:
                    return new Result(Action.VERSION, null, dataDir);
                case DIAGNOSTICS:
                    diagnostics = true;
                    if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                        diagFile = Path.of(args[++i]);
                    } else {
                        diagFile = Path.of("company-remote-diagnostics.txt");
                    }
                    break;
                case DATA_DIR:
                    if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                        dataDir = Path.of(args[++i]);
                    }
                    break;
                default:
                    break;
            }
        }
        // parse the whole argument list so --data-dir after --diagnostics is honored
        if (diagnostics) {
            return new Result(Action.DIAGNOSTICS, diagFile, dataDir);
        }
        return Result.launch(dataDir);
    }
}