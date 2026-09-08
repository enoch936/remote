package com.company.remoteaccess;

import com.company.remoteaccess.core.configuration.AppConfig;
import com.company.remoteaccess.core.configuration.ConfigException;
import com.company.remoteaccess.diagnostics.Diagnostics;
import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.platform.DataDirs;
import com.company.remoteaccess.platform.RequirementChecker;
import javafx.application.Application;

import java.nio.file.Path;

/**
 * Plain {@code main()} entry point for unpackaged / IDE runs. Handles headless
 * CLI flags (version, diagnostics, data directory) before launching JavaFX.
 * Keeps the app non-modular so packaging stays simple.
 */
public class Launcher {

    public static void main(String[] args) {
        Cli.Result cli = Cli.parse(args);
        try {
            switch (cli.action()) {
                case VERSION -> {
                    System.out.println(BuildInfo.version());
                    return;
                }
                case DIAGNOSTICS -> {
                    runDiagnostics(cli.diagnosticsFile(), cli.dataDir());
                    return;
                }
                default -> {
                    if (cli.dataDir() != null) {
                        System.setProperty(DataDirs.PROPERTY, cli.dataDir().toString());
                    }
                }
            }
            Application.launch(MainApp.class, args);
        } catch (Throwable t) {
            System.err.println("FATAL: " + t);
            t.printStackTrace();
        }
    }

    private static void runDiagnostics(Path outFile, Path dataDirOverride) throws Exception {
        if (dataDirOverride != null) {
            System.setProperty(DataDirs.PROPERTY, dataDirOverride.toString());
        }
        com.company.remoteaccess.AppContext ctx = new com.company.remoteaccess.AppContext(DataDirs.resolveBaseDir());
        ctx.configureLogging();
        AppConfig cfg;
        try {
            ctx.loadConfig();
            cfg = ctx.config();
        } catch (ConfigException e) {
            // diagnostics must stay useful even when the configuration is corrupt/tampered
            AppLogger.getLogger().error(LogCategory.SYSTEM, e,
                    "configuration could not be loaded: %s", e.getMessage());
            cfg = AppConfig.create();
        }
        String wgDir = cfg.wgBinaryDir();
        boolean startupEnabled = new com.company.remoteaccess.startup.StartupManager(ctx.runner).isEnabled();
        var requirements = RequirementChecker.survey(ctx.runner, wgDir, true, ctx.configManager.exists());
        Diagnostics.Report report = Diagnostics.gather(
                ctx, ctx.network.isOnline(), requirements, startupEnabled);
        String rendered = Diagnostics.write(outFile, report);
        System.out.println(rendered);
        System.out.println("diagnostics written to " + outFile.toAbsolutePath());
    }
}