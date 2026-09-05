package com.company.remoteaccess.core.configuration;

import com.company.remoteaccess.core.state.Role;
import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;
import com.company.remoteaccess.util.Yaml;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Map;

/**
 * Loads/saves the application configuration file. Non-secret settings only.
 * Writes are atomic (temp file + move) and previous versions are backed up.
 */
public final class ConfigManager {

    private final Path file;

    public ConfigManager(Path file) {
        this.file = file;
    }

    public boolean exists() {
        return file != null && Files.exists(file);
    }

    /** Load configuration, returning a default when unconfigured. */
    public AppConfig load() {
        if (!exists()) {
            AppLogger.getLogger().info(LogCategory.SYSTEM, "no configuration found; using defaults");
            return AppConfig.create();
        }
        try {
            String text = Files.readString(file, StandardCharsets.UTF_8);
            Map<String, Object> data = Yaml.parse(text);
            int version = data.get("version") instanceof Number n
                    ? n.intValue()
                    : (data.get("version") == null ? 0 : Integer.parseInt(String.valueOf(data.get("version"))));
            if (version > AppConfig.CURRENT_VERSION) {
                throw new ConfigException(ConfigException.Kind.NEWER_VERSION,
                        "configuration was written by a newer application version; please upgrade");
            }
            AppConfig cfg = AppConfig.fromMap(data);
            var issues = ConfigValidator.validate(cfg);
            boolean fatal = issues.stream().anyMatch(i -> i.severity == ConfigValidator.Issue.Severity.ERROR);
            if (fatal) {
                StringBuilder msg = new StringBuilder("configuration is invalid:");
                issues.stream().filter(i -> i.severity == ConfigValidator.Issue.Severity.ERROR)
                        .forEach(i -> msg.append("\n - ").append(i.message));
                throw new ConfigException(ConfigException.Kind.INVALID, msg.toString());
            }
            return cfg;
        } catch (ConfigException e) {
            throw e;
        } catch (Exception e) {
            throw new ConfigException(ConfigException.Kind.PARSE_ERROR,
                    "configuration could not be parsed: " + e.getMessage(), e);
        }
    }

    public synchronized void save(AppConfig config) throws IOException {
        if (file == null) {
            throw new IOException("no configuration file path");
        }
        Files.createDirectories(file.toAbsolutePath().getParent());
        String yaml = Yaml.serialize(config.asMap());
        Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
        Files.writeString(tmp, yaml, StandardCharsets.UTF_8);
        if (Files.exists(file)) {
            Path backup = file.resolveSibling(file.getFileName() + ".bak");
            Files.move(file, backup, StandardCopyOption.REPLACE_EXISTING);
        }
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
        AppLogger.getLogger().info(LogCategory.SYSTEM, "configuration saved (%s mode)",
                config.mode() == Role.SERVER ? "server" : "client");
    }
}