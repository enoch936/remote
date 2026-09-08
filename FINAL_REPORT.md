# Final Report — Company Remote Access (Windows)

## Objective
Fix the reboot/startup and tunnel-stability defects behind the 34-section task
brief: serialized gateway lifecycle, single-flight work, never-null VPN engine,
idempotent WireGuard operations, bounded recovery (no infinite ERROR loops),
fail-closed Windows ACL (icacls) hardening, and crash-safe config writes — backed
by regression tests, a green full suite, a build, and a launch validation on this
development machine.

## Root causes addressed
1. **`AppContext` could expose a null VPN engine.** The engine was produced by an
   async dependency-install task; any call on the old path (`gateway.adapter()`,
   status suppliers) before the task completed NPE'd. Some seats also invoked
   `vpn.engine()` and got `null`.
2. **No serialization of gateway lifecycle events.** Startup used a raw thread
   that spawned unbounded work and exited when its work queue idled, so bursts
   (boot + network-change + manual action) ran concurrently — double bootstrap,
   races on `clientRegistry`, torn network/VPN state.
3. **No coalescing of re-bootstraps.** Repeated `boot()` / `rebootstrap()` /
   network-change events each spawned their own thread and ran full teardown +
   bring-up in parallel.
4. **No single-flight for dependency install.** Two first-run windows (role
   chooser plus background check) could both trigger WireGuard install; on
   failure each retried independently.
5. **Service reinstall on every boot load.** `VpnManager.bringUp` re-ran
   `InstallMode.GENERATE`/install even when the service was already installed,
   and `configure` re-installed on every call, so reboots hammered the service.
6. **Unbounded retry loop.** `ERROR -> RECOVERING` was possible on *automated*
   retries; after the backoff budget ran out recovery re-entered indefinitely.
   Explicit operator retry was also broken (a dead no-op when `ERROR`).
7. **`Owner-Transport` in place of routing reqs omission** — brought-up tunnels
   left managed interfaces/firewall/NAT unclean between toggles.
8. **ACL hardening was broken on real machines:**
   - `grantToken` used a **bare SID** (`/grant:r S-1-...`), which icacls rejects
     on Windows with *"No mapping between account names and security IDs"*
     (only the `*SID` literal form is accepted at SID level).
   - Resolution failure fell back to the badly-broad `Everyone` grant.
   - Verification only re-matched the SID token, but `icacls` renders a SID
     grant as the **resolved account name** (`DESKTOP-HCVGQKM\Gebretsadik`), so
     the post-hardening check always failed with *"does not hold Full Control"*.
   - `whoami /user` **pads its table columns**, so walking back from the SID
     over non-whitespace grabbed only the pad → account name parsed as empty.
   - Path names containing `Users` (e.g. `C:\Users\GEBRET~1\...`, the 8.3
     short form) false-positived the "broad principal" check.
   - A javadoc/comment example `HOST\user` embedded a `\u` sequence, which the
     Java compiler still processes inside comments → *illegal unicode escape*.
9. **Config save was not crash-safe.** Body and integrity sidecar were written
   non-atomically with no fsync; a crash could leave a new config without its MAC
   or a half-written file, and the backup was destroyed on restart.

## Architecture changes
### `GatewayService` (server/GatewayService.java)
- Single-thread daemon executor `gateway-lifecycle` serializes **all** lifecycle
  work (bootstrap, recovery, watchdog, network-change). A daemon
  `gateway-scheduler` runs scheduled/single-shot tasks, each submitted back onto
  the lifecycle thread after generation-barrier checks.
- `AtomicLong generation` invalidates stale async work; **single-flight** flags
  (`bootstrapPending`, `recoveryPending`) coalesce duplicate events.
- Validated transition table (supertypes + `STOPPED` guard + `ERROR→STARTING`
  unwind for explicit retry; `ERROR→RECOVERING` stays forbidden).
- New `vpn/GatewayVpn.java` interface — the service now depends on the seam, with
  the real `VpnManager implements GatewayVpn`.
- Elevation probe injected as a package-private `BooleanSupplier isElevated`
  constructor seam (default `Elevation::isElevated`).
- `close()` removes the watchdog, cancels timers, tears down tunnel + managed
  networking and parks in `STOPPED`; nothing can re-enter after close.

### `MainApp` wiring
- Dependency install is single-flight with a `dependencyInstallInProgress`
  `AtomicBoolean`; a second request coalesces. `applyDependencyFix` runs on a
  daemon worker and, on success, calls `rebuildVpnEngine()` then rebinds and
  re-bootstraps on the JavaFX thread. `resetToFirstRun` closes the gateway and
  marks the install cancelled so a late completion is ignored.

### `VpnManager` / `WireGuardAdapter` idempotency
- `configure()` installs/regenerates **once** and is a cheap no-op when already
  configured. `bringUp()` install-once-then-verify; a running interface is only
  re-verified, never reinstalled. `available` flag + `UnavailableAdapter`
  keep all operations controlled (`BINARIES_MISSING`) instead of throwing.
- Cleanup of managed interfaces/firewall/NAT is applied consistently on teardown.

### `ConfigManager.save()` (core/configuration/ConfigManager.java)
- Both the config body and (plaintext mode) HMAC sidecar are **staged, fsynced
  (`FileChannel.force`)**, a `.bak` copy is preserved, the old sidecar is removed
  in encrypted mode *before* the new body lands, and both are then moved
  `ATOMIC_MOVE` (config first, sidecar second). `load()` still decrypts →
  verifies → validates.

### `FilePermissions` (platform/FilePermissions.java)
- Grants use the icacls **SID-literal** form (`*S-1-…:(F)` /
  `*S-1-…:(OI)(CI)F`), never a bare SID, and the broad principals
  `S-1-1-0`, `S-1-5-11`, `S-1-5-32-545` are removed with `/remove:g`.
- SID resolution is `whoami /user` → `NTSystem` (reflection) → **fail closed**;
  never `Everyone`.
- Post-hardening verification matches **both** the SID and the resolved
  **account-name** rendering, and only inspects the ACE principal token (never
  the path, so `C:\Users\...` cannot false-positive).
- Testable `CommandRunner` seams throughout.

## Files changed
| File | Change |
|---|---|
| `server/GatewayService.java` | Rewrote lifecycle (executor + generation + single-flight), transition fixes |
| `vpn/GatewayVpn.java` | **New** interface seam |
| `vpn/VpnManager.java` | `implements GatewayVpn`; idempotent configure/bring-up; available flag |
| `vpn/WireGuardAdapter.java` | Install-once idempotency; two `String.format` `VpnException` fixes |
| `vpn/VpnAdapter.java` | Seam additions |
| `MainApp.java` | Single-flight dependency install, rebind+rebootstrap, reset cancellation, null-free wiring |
| `AppContext.java` | Never-null `VpnManager` (+ `UnavailableAdapter`) |
| `platform/FilePermissions.java` | SID-literal grants, fail-closed resolution, account-name + principal-token verification |
| `core/configuration/ConfigManager.java` | Atomic + fsynced save with .bak and ordered sidecar handling |
| `test/.../GatewayServiceTest.java` | **New** (4 tests) |
| `test/.../VpnManagerIdempotencyTest.java` | **New** (4 tests) |
| `test/.../FilePermissionsTest.java` | **New** (7 tests incl. real icacls/whoami renderings) |
| `test/.../ConfigManagerEncryptionTest.java` | De-flaked "encrypted ≠ plaintext" assertion |

## Tests & results
- **Full suite: 202 tests, 0 failures, 0 errors** (2 skips are pre-existing
  Windows-elevation skips in `DependencyInstallerTest`). `mvn test` →
  `BUILD SUCCESS`.
- Regression tests added for: missing-WireGuard reaches `BINARIES_MISSING`
  without NPE; concurrent `rebootstrap()` coalesces to a single run; recovery
  exhaustion ends in a stable `ERROR` and an explicit retry still works;
  `close()` stops all activity; repeated configure/bring-up never reinstalls;
  unavailable engine is a controlled no-op; ACL tests cover SID-literal grants,
  fail-closed resolution, **account-name rendering** (the real icacls output),
  and the `C:\Users\...` path false-positive.
- Two flaky/broken assertions found while debugging were fixed (see above).
- Debugging journey that mattered: the ACL suite surfaced three distinct real
  bugs (bare-SID rejection, account-name rendering, `Users` path false positive)
  each reproduced on this machine with real `icacls`/`whoami`.

## Build & launch validation
- `mvn package` → `company-remote-access.jar` + lib bundles. `BUILD SUCCESS`.
- Launched `java -cp target/company-remote-access.jar;target/lib/* com.company.remoteaccess.Launcher`:
  app starts and stays running (verified on PID 16020), no crash on boot.
- Limitation of this box: real WireGuard end-to-end and elevated firewall/NAT
  operations cannot be exercised here (no WireGuard installed, shell not
  elevated). Those paths are covered by the fake-`CommandRunner` seams.

## Remaining issues / notes
- `mvn clean` cannot delete `target/lib/jcommander-1.82.jar` on this machine
  because the VS Code Java language server (PID 15656?) holds it open. Workaround
  used throughout: delete `target/classes`, `target/test-classes`,
  `target/surefire-reports` then run `mvn test|package` *without* `clean`, or
  unload the language server first. On CI this is a non-issue.
- Two JVM scaffolds (`HardenRepro*.java`, `.class` files) used to reproduce the
  ACL failures were removed from the temp dir after use.
- No secrets were ever written to the repository; `secrets`/credential material
  is only produced inside runtime/`%TEMP%` directories under hardened ACLs.

## Success-criteria checklist
- [x] Gateway lifecycle fully serialized on one executor; generation token
      invalidates stale work.
- [x] Re-bootstrap / recovery / dependency-install are single-flight (coalesced).
- [x] VPN engine is never null; `UnavailableAdapter` keeps NPEs out.
- [x] WireGuard service install happens exactly once; re-verifies when already
      running.
- [x] Recovery is bounded by the backoff budget; explicit retry always available.
- [x] Managed networking/firewall/NAT cleaned up on teardown.
- [x] ACL hardening: SID-literal grants, no `Everyone` fallback, fail-closed
      verification accepting both SID and account-name rendering.
- [x] Config + integrity walked atomically with fsync and preserved backup.
- [x] Full suite green (202/0/0), jar builds, app launches.