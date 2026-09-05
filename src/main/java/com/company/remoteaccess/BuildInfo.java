package com.company.remoteaccess;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/** Reads build metadata from app.properties. */
public final class BuildInfo {

    private static final Properties PROPS = new Properties();

    static {
        try (InputStream in = BuildInfo.class.getResourceAsStream("/app.properties")) {
            if (in != null) {
                PROPS.load(in);
            }
        } catch (IOException ignored) {
            // defaults below
        }
    }

    private BuildInfo() {
    }

    public static String name() {
        return PROPS.getProperty("app.name", "Company Remote Access");
    }

    public static String version() {
        return PROPS.getProperty("app.version", "1.0.0");
    }

    public static String versionLabel() {
        return "v" + version();
    }
}