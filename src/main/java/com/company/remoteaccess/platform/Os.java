package com.company.remoteaccess.platform;

/** Runtime/platform detection helpers. */
public final class Os {

    public enum Family { WINDOWS, LINUX, MACOS, OTHER }

    private static final Family FAMILY = detect();

    private Os() {
    }

    public static Family family() {
        return FAMILY;
    }

    public static boolean isWindows() {
        return FAMILY == Family.WINDOWS;
    }

    public static boolean isLinux() {
        return FAMILY == Family.LINUX;
    }

    public static boolean isMacos() {
        return FAMILY == Family.MACOS;
    }

    private static Family detect() {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("win")) {
            return Family.WINDOWS;
        }
        if (os.contains("linux")) {
            return Family.LINUX;
        }
        if (os.contains("mac") || os.contains("darwin")) {
            return Family.MACOS;
        }
        return Family.OTHER;
    }
}