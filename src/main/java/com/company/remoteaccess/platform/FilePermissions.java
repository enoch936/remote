package com.company.remoteaccess.platform;

import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/**
 * Restricts file and directory permissions to the current account using the
 * operating system's own tools (Windows {@code icacls}, POSIX chmod).
 *
 * <p>Windows hardening is fail-closed:
 * <ul>
 *   <li>grants are applied using the icacls <em>SID literal</em> form
 *       ({@code *&lt;SID&gt;}) so no name-to-SID mapping is attempted (a bare
 *       SID is treated by icacls as an account name and fails with "No mapping
 *       between account names and security IDs was done");</li>
 *   <li>inheritance is removed and broad principals (Everyone, Authenticated
 *       Users, Users) are explicitly stripped;</li>
 *   <li>the resulting ACL is verified (current user holds Full Control and no
 *       broad principal remains); if SID resolution or verification fails an
 *       {@link IOException} is thrown and no "Everyone" fallback is ever used.</li>
 * </ul>
 */
public final class FilePermissions {

    /** Everyone */
    static final String SID_EVERYONE = "S-1-1-0";
    /** Authenticated Users */
    static final String SID_AUTHENTICATED_USERS = "S-1-5-11";
    /** Users */
    static final String SID_USERS_GROUP = "S-1-5-32-545";

    static final Set<String> BROAD_SIDS = Set.of(
            SID_EVERYONE, SID_AUTHENTICATED_USERS, SID_USERS_GROUP);

    private FilePermissions() {
    }

    public static void hardenFile(Path file) throws IOException {
        hardenFile(file, new CommandRunner());
    }

    public static void hardenDirectory(Path dir) throws IOException {
        hardenDirectory(dir, new CommandRunner());
    }

    /** Package-visible seam so tests can inject a fake {@link CommandRunner}. */
    static void hardenFile(Path file, CommandRunner runner) throws IOException {
        AppLogger.getLogger().debug(LogCategory.SECURITY, "hardening permissions for %s", file);
        switch (Os.family()) {
            case WINDOWS -> hardenWindows(file, false, runner);
            default -> {
                CommandResult r = runner.run(command("chmod", "600", file.toAbsolutePath().toString()));
                if (r.failed()) {
                    throw new IOException("chmod hardening of " + file + " failed: " + r.stderr());
                }
            }
        }
    }

    /** Package-visible seam so tests can inject a fake {@link CommandRunner}. */
    static void hardenDirectory(Path dir, CommandRunner runner) throws IOException {
        if (!Files.isDirectory(dir)) {
            Files.createDirectories(dir);
        }
        AppLogger.getLogger().debug(LogCategory.SECURITY, "hardening directory %s", dir);
        switch (Os.family()) {
            case WINDOWS -> hardenWindows(dir, true, runner);
            default -> {
                CommandResult r = runner.run(command("chmod", "700", dir.toAbsolutePath().toString()));
                if (r.failed()) {
                    throw new IOException("chmod hardening of " + dir + " failed: " + r.stderr());
                }
            }
        }
    }

    private static void hardenWindows(Path target, boolean directory, CommandRunner runner)
            throws IOException {
        String path = target.toAbsolutePath().toString();
        CurrentIdentity identity = resolveCurrentIdentity(runner, true);
        List<String> icacls = new java.util.ArrayList<>(List.of(
                "icacls", path, "/inheritance:r",
                "/grant:r", grantToken(identity.sid(), directory)));
        for (String broad : BROAD_SIDS) {
            icacls.add("/remove:g");
            icacls.add("*" + broad);
        }
        CommandResult r = runner.run(icacls, 60);
        if (r.failed()) {
            throw new IOException("icacls hardening of " + path + " failed: " + r.stderr());
        }
        CommandResult listing = runner.run(List.of("icacls", path), 60);
        if (listing.failed()) {
            throw new IOException("unable to verify ACL of " + path + ": " + listing.stderr());
        }
        // icacls usually renders our grant as the resolved account name
        // (for example HOST + backslash + user) rather than the SID, so
        // verification accepts both forms.
        if (!ownerHasFullControl(listing.stdout(), identity.sid(), identity.accountName())) {
            throw new IOException("ACL verification failed: current user does not hold "
                    + "Full Control on " + path);
        }
        if (!broadPrincipalsAbsent(listing.stdout())) {
            throw new IOException("ACL verification failed: broad principal still present on " + path);
        }
    }

    // ------------------------------------------------------------------
    // SID resolution
    // ------------------------------------------------------------------

    /** The resolved current account: SID plus (if known) the display name form. */
    record CurrentIdentity(String sid, String accountName) {
    }

    /**
     * Resolve the current user's SID; never falls back to a broad principal.
     * Resolution order: {@code whoami /user}, then {@code NTSystem#getSID} via
     * reflection (avoids a hard compile-time dependency on {@code jdk.security.auth}),
     * then failure.
     */
    static String resolveCurrentUserSid(CommandRunner runner) throws IOException {
        return resolveCurrentIdentity(runner, true).sid();
    }

    /** Package-visible: {@code allowNtSystem=false} for deterministic tests. */
    static CurrentIdentity resolveCurrentIdentity(CommandRunner runner, boolean allowNtSystem)
            throws IOException {
        CommandResult whoami = runner.run(List.of("whoami", "/user"), 20);
        if (whoami.success()) {
            CurrentIdentity fromWhoami = parseIdentity(whoami.stdout());
            if (fromWhoami != null && fromWhoami.sid() != null) {
                return fromWhoami;
            }
        }
        if (allowNtSystem) {
            String ntSid = sidFromNtSystem();
            if (ntSid != null) {
                return new CurrentIdentity(ntSid, System.getProperty("user.name"));
            }
        }
        throw new IOException("unable to resolve current user SID (whoami and NTSystem both failed); "
                + "refusing to harden with a broad principal");
    }

    static String sidFromWhoami(CommandResult whoami) {
        if (whoami == null || !whoami.success()) {
            return null;
        }
        return parseSid(whoami.stdout());
    }

    /** Locate the S-1- SID token in a {@code whoami /user} output block. */
    static String parseSid(String whoamiOutput) {
        CurrentIdentity id = parseIdentity(whoamiOutput);
        return id == null ? null : id.sid();
    }

    /** Extract the account display token (e.g. {@code host<sep>user}) beside the SID. */
    static String parseAccountName(String whoamiOutput) {
        CurrentIdentity id = parseIdentity(whoamiOutput);
        return id == null ? null : id.accountName();
    }

    static CurrentIdentity parseIdentity(String whoamiOutput) {
        if (whoamiOutput == null) {
            return null;
        }
        int i = whoamiOutput.indexOf("S-1-");
        if (i < 0) {
            return null;
        }
        // whoami pads each table column with spaces, so the account token is
        // the last non-whitespace run to the left of the SID (past the padding).
        int accountEnd = i;
        while (accountEnd > 0 && Character.isWhitespace(whoamiOutput.charAt(accountEnd - 1))) {
            accountEnd--;
        }
        int accountStart = accountEnd;
        while (accountStart > 0 && !Character.isWhitespace(whoamiOutput.charAt(accountStart - 1))) {
            accountStart--;
        }
        String account = whoamiOutput.substring(accountStart, accountEnd);
        if (account.indexOf('\n') >= 0 || account.indexOf('\r') >= 0) {
            account = "";
        }
        StringBuilder sid = new StringBuilder();
        for (int j = i; j < whoamiOutput.length(); j++) {
            char c = whoamiOutput.charAt(j);
            if (Character.isWhitespace(c) || c == ':' || c == ';') {
                break;
            }
            sid.append(c);
        }
        String sidStr = sid.toString().trim();
        return sidStr.startsWith("S-1-")
                ? new CurrentIdentity(sidStr, account.isEmpty() ? null : account)
                : null;
    }

    private static String sidFromNtSystem() {
        try {
            Class<?> nt = Class.forName("com.sun.security.auth.module.NTSystem");
            Object instance = nt.getDeclaredConstructor().newInstance();
            String sid = (String) nt.getMethod("getSID").invoke(instance);
            return (sid != null && sid.startsWith("S-1-")) ? sid : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    // ------------------------------------------------------------------
    // icacls argument / ACL verification helpers (pure, tested)
    // ------------------------------------------------------------------

    /** icacls grant token: {@code *SID:(F)} for files, {@code *SID:(OI)(CI)F} for dirs. */
    static String grantToken(String sid, boolean directory) {
        if (sid == null || !sid.startsWith("S-1-")) {
            throw new IllegalArgumentException("invalid SID: " + sid);
        }
        return "*" + sid + (directory ? ":(OI)(CI)F" : ":(F)");
    }

    /** True when the owner SID (or its display name) holds Full Control and no deny. */
    static boolean ownerHasFullControl(String aclListing, String sid) {
        return ownerHasFullControl(aclListing, sid, null);
    }

    static boolean ownerHasFullControl(String aclListing, String sid, String accountName) {
        if (aclListing == null || sid == null) {
            return false;
        }
        String accountLower = accountName == null ? null : accountName.toLowerCase(java.util.Locale.ROOT);
        boolean granted = false;
        for (String line : aclListing.split("\\r?\\n")) {
            String lineLower = line.toLowerCase(java.util.Locale.ROOT);
            boolean idMatches = line.contains(sid)
                    || (accountLower != null && lineLower.contains(accountLower));
            if (idMatches && line.contains("(D)")) {
                return false;
            }
            if (idMatches && (line.contains("(F)") || aclTokenHoldsFullControl(line))) {
                granted = true;
            }
        }
        return granted;
    }

    /** True when no broad principal (Everyone/Authenticated Users/Users) is listed. */
    static boolean broadPrincipalsAbsent(String aclListing) {
        if (aclListing == null) {
            return false;
        }
        for (String line : aclListing.split("\\r?\\n")) {
            if (broadPrincipalPresent(line)) {
                return false;
            }
        }
        return true;
    }

    private static boolean broadPrincipalPresent(String line) {
        for (String broad : BROAD_SIDS) {
            if (line.contains(broad)) {
                return true;
            }
        }
        // Display-name forms: only inspect the ACE principal token (the last
        // whitespace-delimited token that carries the perms). The path prefix is
        // never checked, or "C:\Users\..." would false-positive on "users".
        String ace = trailingAceToken(line);
        if (ace == null) {
            return false;
        }
        String l = ace.toLowerCase(java.util.Locale.ROOT);
        return l.matches(".*\\b(everyone|authenticated users)\\b.*")
                || l.matches("(^|[^a-z])users([^a-z]|$).*");
    }

    /** Last whitespace-delimited token of an icacls line when it carries perms. */
    private static String trailingAceToken(String line) {
        if (line == null || line.isBlank()) {
            return null;
        }
        String[] tokens = line.trim().split("\\s+");
        String ace = tokens[tokens.length - 1];
        return ace.contains(":") && ace.contains("(") ? ace : null;
    }

    private static boolean aclTokenHoldsFullControl(String line) {
        int colon = line.indexOf(':');
        String perms = colon >= 0 ? line.substring(colon + 1) : line;
        return perms.contains("F");
    }

    private static List<String> command(String... parts) {
        return java.util.Arrays.asList(parts);
    }
}