package com.company.remoteaccess.platform;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** ACL hardening regressions: SID-literal grants, fail-closed SID resolution,
 *  broad-principal removal and post-hardening verification. */
class FilePermissionsTest {

    private static final String SID = "S-1-5-21-1404788801-2529766130-2047420871-1001";

    @TempDir
    Path tmp;

    @Test
    void grantTokenUsesIaclsSidLiteralNotBareSid() {
        assertEquals("*" + SID + ":(F)", FilePermissions.grantToken(SID, false));
        assertEquals("*" + SID + ":(OI)(CI)F", FilePermissions.grantToken(SID, true));
        assertThrows(IllegalArgumentException.class, () -> FilePermissions.grantToken("Everyone", false));
        assertThrows(IllegalArgumentException.class, () -> FilePermissions.grantToken("", true));
    }

    @Test
    void parseSidExtractsTokenFromWhoamiOutput() {
        String out = "USER INFORMATION\n-----------------\n\n"
                + "User Name           SID\n"
                + "==================  ============================================\n"
                + "host\\gtest          " + SID + "\n";
        assertEquals(SID, FilePermissions.parseSid(out));
        assertEquals("host\\gtest", FilePermissions.parseAccountName(out));
        assertEquals(SID, FilePermissions.parseSid("  " + SID + " \r\n"));
        assertEquals(null, FilePermissions.parseSid("no sid here"));
        assertEquals(null, FilePermissions.parseSid(null));
        // real whoami pads the account column with spaces before the SID
        String padded = "desktop-hcvgqkm\\gebretsadik                " + SID + "\n";
        assertEquals(SID, FilePermissions.parseSid(padded));
        assertEquals("desktop-hcvgqkm\\gebretsadik", FilePermissions.parseAccountName(padded));
    }

    @Test
    void resolveCurrentUserSidFailsClosedWhenResolutionFails() {
        CommandRunner failing = new CommandRunner() {
            @Override
            public CommandResult run(List<String> command, long timeoutSeconds) {
                return new CommandResult(1, "", "whoami not found");
            }
        };
        IOException ex = assertThrows(IOException.class,
                () -> FilePermissions.resolveCurrentIdentity(failing, false));
        assertFalse(ex.getMessage().contains("Everyone"),
                "never fall back to granting Everyone");
    }

    @Test
    void ownerHasFullControlAndBroadPrincipalsVerification() {
        String locked = "C:\\data NT AUTHORITY\\SYSTEM:(I)(F)\n"
                + "          BUILTIN\\Administrators:(I)(F)\n"
                + "          *" + SID + ":(F)\n";
        assertTrue(FilePermissions.ownerHasFullControl(locked, SID));
        assertTrue(FilePermissions.broadPrincipalsAbsent(locked));
        assertFalse(FilePermissions.broadPrincipalsAbsent(locked + " *S-1-1-0:(D)\n"));
        assertFalse(FilePermissions.broadPrincipalsAbsent(
                " C:\\x Everyone:(F)\n"));
        assertFalse(FilePermissions.broadPrincipalsAbsent(
                " C:\\x NT AUTHORITY\\Authenticated Users:(OI)(CI)F\n"));

        String readOnly = "C:\\data *" + SID + ":(R)\n";
        assertFalse(FilePermissions.ownerHasFullControl(readOnly, SID));
        assertFalse(FilePermissions.ownerHasFullControl(locked, "S-1-5-21-999"));
        assertFalse(FilePermissions.ownerHasFullControl(null, SID));
        String denied = "C:\\data *" + SID + ":(D)(F)\n";
        assertFalse(FilePermissions.ownerHasFullControl(denied, SID));
    }

    @Test
    void verificationAcceptsIaclsAccountNameRendering() {
        // icacls usually renders the grant as the resolved account name, not the SID
        String rendered = "C:\\data DESKTOP-HCVGQKM\\Gebretsadik:(OI)(CI)(F)\n";
        assertTrue(FilePermissions.ownerHasFullControl(rendered, SID, "desktop-hcvgqkm\\gebretsadik"));
        assertFalse(FilePermissions.ownerHasFullControl(rendered, SID));
    }

    @Test
    void hardenFileIssuesSidLiteralGrantsAndVerifies() throws IOException {
        Path file = Files.writeString(tmp.resolve("secret.txt"), "data");
        List<List<String>> executed = new ArrayList<>();
        CommandRunner fake = new CommandRunner() {
            @Override
            public CommandResult run(List<String> command, long timeoutSeconds) {
                executed.add(command);
                if (command.get(0).equals("whoami")) {
                    return new CommandResult(0, "host\\u " + SID + "\n", "");
                }
                if (command.get(0).equals("icacls") && command.size() > 2
                        && command.get(1).equals(file.toAbsolutePath().toString())
                        && command.get(2).equals("/inherit" + "ance:r")) {
                    return new CommandResult(0, "", "");
                }
                if (command.get(0).equals("icacls") && command.size() == 2) {
                    return new CommandResult(0,
                            "file.txt NT AUTHORITY\\SYSTEM:(I)(F)\n *" + SID + ":(F)\n", "");
                }
                return new CommandResult(0, "", "");
            }
        };
        FilePermissions.hardenFile(file, fake);
        List<String> grant = executed.stream()
                .filter(c -> c.contains("/grant:r"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no icacls grant command issued"));
        assertTrue(grant.contains("*" + SID + ":(F)"),
                "grant must use the icacls SID-literal form");
        assertTrue(grant.contains("/inherit" + "ance:r"));
        assertTrue(grant.contains("/remove:g"));
        assertTrue(grant.contains("*S-1-1-0"));
        assertFalse(grant.contains("/grant:r") && grant.stream()
                        .anyMatch(a -> a.startsWith("S-1-") && !a.startsWith("*S-1-")),
                "a bare SID must never be passed to icacls as an account name");
    }

    @Test
    void hardenFileVerificationFailureFailsClosed() {
        Path file = tmp.resolve("other.txt");
        try {
            Files.writeString(file, "data");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        CommandRunner fake = new CommandRunner() {
            @Override
            public CommandResult run(List<String> command, long timeoutSeconds) {
                if (command.get(0).equals("whoami")) {
                    return new CommandResult(0, SID + "\n", "");
                }
                if (command.size() == 2 && command.get(0).equals("icacls")) {
                    // ACL still grants Everyone; hardening must not pass silently
                    return new CommandResult(0, "file.txt Everyone:(F)\n", "");
                }
                return new CommandResult(0, "", "");
            }
        };
        assertThrows(IOException.class, () -> FilePermissions.hardenFile(file, fake));
    }
}