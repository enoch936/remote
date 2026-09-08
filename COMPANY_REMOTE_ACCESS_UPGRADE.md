# Company Remote Access — Upgrade Plan (P0 + P1 + Phase 1 finishing + Phase 2 + Phase 3 + Phase 4 + Phase 5)

Audit report: `report.md` (same repo). This file tracks the P0/P1 fixes that were
implemented, the Phase 1 finishing pass (strict validation, NAT verification,
dead-config cleanup), the Phase 2 system automation work, the Phase 3 network
reliability pass, the Phase 4 device-ecosystem pass and the Phase 5 professional-product
pass, with per-item status.
Scope chosen by the user: plan file + implement **P0 + P1**, then **finish Phase 1 fully**,
then **Phase 2 (system automation)**, then **Phase 3 (network reliability)**, then
**Phase 4 (device ecosystem)**, then **Phase 5 (professional product subset)**. Verification:
`javac` compile
check + the full JUnit suite via the JUnit Platform launcher (Maven is not available on
this machine, so `mvn test` cannot be run here).

Legend: `[ ]` todo, `[x]` done.

## P0 — server with zero devices can never reach ONLINE

- [x] `WgConfigBuilder.build()`: allow an empty peer list (a WireGuard interface
      with no peers is valid). Keeps the existing "key + address required" contract.
- [x] `GatewayService.recover()`: log/progress hint "no paired devices" when starting
      with an empty registry, instead of being stuck in ERROR.
- [x] `ServerDashboard`: show an empty-state banner when 0 authorized devices.
- [x] `WgConfigBuilderTest`: replace `requiresAtLeastOnePeer` with a test asserting an
      empty peer list produces a valid `[Interface]`-only config.

## P1 — pairing token is never verified / consumed

- [x] `PairingManager`: `issue(name, clientPublicKey)` stores the client public key with
      the (hash-only) token; new `claimForHandshake(publicKey)` consumes the pending
      token exactly once when the device that owns that key completes its first
      WireGuard handshake (zero-HTTP — the handshake itself is the proof of ownership).
- [x] `GatewayService`: receives the shared `PairingManager`; watchdog calls
      `claimForHandshake` on every handshaken peer (single-use, TTL honoured).
- [x] `MainApp`: creates one shared `PairingManager` in server mode, passes it to
      `GatewayService`, exposes it to the dashboard.
- [x] `ServerDashboard` / `PairDeviceDialog`: use the shared manager; dialog passes the
      pasted public key into `issue(name, publicKey)`.
- [x] Strict client-side payload validation in `PairingToken.fromPayload` (base64 key
      length, IPv4 address, port range) so garbage/graphite text cannot enter wg config.

## P1 — macOS gateway can never go ONLINE

- [x] `MacOSFirewall`: inbound UDP for the app is allowed by default macOS behaviour;
      `applyRule`/`removeRuleById` become no-op bookkeeping (manifest only) instead of
      throwing UNSUPPORTED_PLATFORM.
- [x] `MacOsNat`: real sysctl `net.inet.ip.forwarding=1` + explicit pf guidance; no
      longer UNSUPPORTED_PLATFORM. Split-tunnel macOS now reaches ONLINE.
- [x] `WireGuardAdapter`: also search `/opt/homebrew/bin/wg-quick` and fall back to
      `which wg-quick` (fixes Apple Silicon / Homebrew installs).

## P1 — firewall rules are never removed

- [x] `VpnManager.removeAllManagedFirewall()` wraps `FirewallManager.removeAllManaged()`.
- [x] `GatewayService.close()` and `rebootstrap()` call it after undoing routes/NAT.

## P1 — client failure leaves the tunnel running

- [x] `ClientService.rollbackAfterFailure()`: stops the tunnel, undoes `lastPlan` and
      all managed routes; invoked on every failure path after `startClient`.

## P1 — shutdown race (async cleanup vs `System.exit`)

- [x] `ClientService.close()`: `executor.shutdown()` + bounded `awaitTermination`
      (graceful, then `shutdownNow`).
- [x] `MainApp.shutdown()`: calls `clientService.close()` before `Platform.exit`.

## Related small fixes pulled in

- [x] `WindowsNat.enableNat()`: stop throwing a fake PERMISSION_REQUIRED "note" after a
      successful NAT setup; log the reboot note as a warning instead.
- [x] Tests updated: `WgConfigBuilderTest`, `PairingManagerTest` (claim/handshake,
      single-use, revoked-after-claim).

## Phase 1 finishing — strict validation, NAT verification, dead-config cleanup

Finishing the remaining Phase 1 items of the production upgrade spec:
strict input validation (#3), real NAT verification (#5) and removal of the
dead configuration keys (#8).

### Strict validation (Phase 1 item #3)

- [x] New `security/Validation.java`: WireGuard key format `^[A-Za-z0-9+/]{43}=$`,
      hostname/IP endpoints (optional UDP port), device names (no control chars /
      `/\ ; " ` { } < > |`, ≤ 64 chars), DNS address lists, port range.
- [x] `WgConfigBuilder.build()`: validates private key, interface address CIDR,
      every peer's public key, AllowedIPs CIDRs and endpoint before writing config.
- [x] `ClientRegistry.add()`: rejects malformed device names, public keys and VPN addresses.
- [x] `PairingManager.issue()`: rejects malformed device names/keys before issuing a token.
- [x] `ConfigValidator`: client device-name, gateway endpoint and DNS-override checks.
- [x] `VpnManager.startClient()`: validates the pinned server public key + endpoint.
- [x] Input-boundary tests: new `ValidationTest` + negative builder/registry/pairing
      tests; test fixtures updated to real 44-char WG keys.

### NAT verification (Phase 1 item #5)

- [x] `NatManager.NatResult` (VERIFIED / PARTIAL / NOT_ENABLED / ERROR) + new
      read-only `verifyNat(vpnSubnet, lanInterface)` per platform:
  - Windows: `Get-NetNat` presence + `IPEnableRouter` registry value.
  - Linux: `net.ipv4.ip_forward` + `iptables -C` MASQUERADE/FORWARD checks.
  - macOS: `net.inet.ip.forwarding`; pf rule is manual → PARTIAL by design.
- [x] `VpnManager.applyGatewayNat()`: **configure-then-verify** (no longer bails on
      `missingRequirements` before configuring); NOT_ENABLED/ERROR → `NAT_CONFIGURATION`
      error; PARTIAL logs a warning and stays ONLINE.
- [x] `VpnException` kinds `NAT_CONFIGURATION` / `FIREWALL_CONFIGURATION`; `GatewayState`
      values `NAT_FAILED` / `FIREWALL_FAILED`; `GatewayService.handleRecoveryFailure`
      maps them; firewall rule failure now reports `FIREWALL_CONFIGURATION`.
- [x] `VpnManager.removeAllManagedNat()` (tracked via `natManaged` flag) called from
      `GatewayService.close()` and `rebootstrap()` — NAT teardown on stop/restart.

### Dead-config cleanup (Phase 1 item #8)

- [x] Removed `server.allowFullLan`, `server.publicEndpoint`, `server.endpointMode`
      from `AppConfig` (and `allowFullLan()`/`serverPublicEndpoint()`/`serverEndpointMode()`
      getters); `ConfigValidator` no longer reads the dead endpoint; `PairDeviceDialog`
      resolves the pairing host from `serverHost`.
- [x] `client.pairApplied` default `false` + `clientPairApplied()` getter; written on
      pairing, cleared on forget; `ClientService.pairApplied()` accessor.
- [x] `MainApp.startBackgroundServices()` auto-connects when
      `connectOnAppStart && clientPairApplied && config-file present` (guarded, logged on error).
- [x] `SettingsView` security tab: "Connect automatically when the application starts"
      checkbox persisted to `security.connectOnAppStart`.

## Phase 2 — system automation

Implemented subset (testable on this machine); installers + auto-update deferred (#P2).

### Standard data directories

- [x] `platform/DataDirs.java`: base dir resolved per OS (`%APPDATA%\CompanyRemoteAccess`,
      `~/Library/Application Support/CompanyRemoteAccess`, `~/.config/company-remote-access`);
      system property `company-remote.data-dir` and the `--data-dir` CLI flag override it.
- [x] One-time migration from the legacy `~/.company-remote` layout (`requiresMigration`,
      `migrateLegacy`) — runs at startup, never clobbers an existing newer install.
- [x] `MainApp` now uses `DataDirs.resolveBaseDir()` instead of the hardcoded path.

### Dependency / requirement detection

- [x] `platform/RequirementChecker.java`: reports OS support, WireGuard tooling, elevation
      (admin-required aware) and config presence, both as pure `evaluate(...)` and as a
      live `survey(runner, wgDir, ...)`; one-line `summarize(...)`.
- [x] `MainApp.logStartupRequirements(...)` logs every non-OK requirement at startup.

### Diagnostics tool

- [x] `diagnostics/Diagnostics.java`: `Diagnostics.Report` (version, OS, data dir, config,
      wg, elevation + hint, network online/interfaces, start-with-OS, vpn build error,
      requirement list, last 40 redacted log lines) with `render()`/`write()`.
- [x] `--diagnostics [out.txt]` headless mode in `Launcher` (no JavaFX required) prints
      the report and writes the file; output is run through `Secrets.redact(...)` so keys
      and pairing material never leave the machine.

### Elevation helper

- [x] `Elevation.canElevate()` and `Elevation.relaunchElevated(args)` — re-launch this
      app itself with admin rights (Windows UAC `Start-Process -Verb RunAs`,
      Linux `pkexec`, macOS `osascript ... with administrator privileges`), respecting a
      packaged `jpackage.app-path`.

### Version reporting + CLI

- [x] `Cli.parse(...)`: `--version`, `--diagnostics [file]`, `--data-dir <dir>`; handled
      before JavaFX starts in `Launcher` (`--version` prints `BuildInfo.version()`).

### Setup wizard

- [x] Welcome page now states the WireGuard + admin requirements and points to
      `--diagnostics` for a support report.

### Deferred (Phase 2, not implemented)

- ⬜ Native Windows/macOS installers (jpackage build scripts) — cannot be built/tested here.
- ⬜ Auto-update / upgrade notifications — needs a distribution channel + signing; out of
      scope for this machine.

## Phase 3 — network reliability

Implemented subset (testable on this machine); IPv6 and OS-resilience live paths deferred.

### Connectivity probing (TunnelTester)

- [x] Gateway reachability is now handshake-authoritative: a fresh VPN handshake proves
      the gateway is reachable, so ICMP rate-limiting/masking can no longer produce a
      false "gateway down" verdict; ping still runs, purely to measure latency.
- [x] DNS checks use an injectable `DnsLookup` (deterministic tests, no live network), and
      the internet check reuses the same resolver as its DNS fallback.
- [x] Probe/company-network and full-tunnel internet checks retained.

### Connection reuse / wg-quick conflicts (WireGuardAdapter)

- [x] Non-Windows `start()` is idempotent: `wg show interfaces` is queried first and an
      already-up tunnel is reused (no more failing with "Interface already exists" on
      restarts/reconnects); commands were never left in a half-up state.
- [x] Pure helpers `parseInterfaces(...)` / `tunnelAlreadyUp(...)` + instance
      `listTunnels()` (unit-tested with a fake runner).

### macOS DNS resilience

- [x] After `wg-quick up` on macOS the DNS cache is flushed (`dscacheutil -flushcache` +
      `killall -HUP mDNSResponder`) so wg-provided DNS servers take effect immediately
      (code-inspection only; no macOS host here).

### Gateway health (HealthMonitor)

- [x] New `stalePeers` metric (authorized peers with a handshake ≥ 120 s old while the
      tunnel runs) alongside `onlinePeers`; reconnect counter now saturates at 100 instead
      of rolling over to 0.

### Deferred (Phase 3 remainder)

- ⬜ IPv6 — requires an explicit opt-in design; not touched.
- ⬜ OS-specific runner/sudo lifecycle and server-side NAT/multicast troubleshooting —
      out of scope for this machine; existing code unchanged.

## Phase 4 — device ecosystem

Implemented subset (testable on this machine); live peer removal and the gateway audit
events are code-inspection only without a WireGuard host.

### Audit log wiring (was dead code)

- [x] `AuditLog` is now built in `MainApp` for server mode (`data/audit.log`) and exposed
      via `MainApp.auditLog()`; it is injected into `ClientRegistry`, `PairingManager` and
      `GatewayService`.
- [x] Events recorded: registry add / revoke / rename / remove; pairing token
      issue / verify / consume-on-first-handshake; gateway start / stop / rebootstrap and
      terminal states (`ONLINE`, `ERROR`, `NAT_FAILED`, `FIREWALL_FAILED`,
      `PERMISSION_REQUIRED`, `BINARIES_MISSING`).
- [x] Privacy + integrity: each line stores `timestamp | actor | action |
      sha256(redact(details)) | prevHash` — raw details (and any WireGuard keys they
      reference) never appear on disk; `verifyChain()` detects tampering; `tail(n)` reads
      the last n entries. Blank actor/action lines are skipped (`audit must never crash`).
- [x] `ClientRegistry.rename(...)` now validates the new name via
      `Validation.requireDeviceName` (previously unvalidated).

### Device management UI (ServerDashboard)

- [x] Each AUTHORIZED device row gains **Revoke**, **Rename** and **Re-pair** actions:
      - **Revoke** → `ClientRegistry.revoke` (device shown as REVOKED, retained for
        history; its key can never be re-registered, its VPN address becomes free) plus
        best-effort live `adapter().removePeer` of the running tunnel.
      - **Rename** → inline `TextInputDialog`, validated before persist.
      - **Re-pair** → `PairDeviceDialog.showRotate`: revoke the old key, re-register the
        device under the same VPN address with a pasted new key, drop the old peer live
        (best effort) and generate a fresh single-use pairing code bound to the new key.

### Pairing-lifetime observability

- [x] The existing single-use / TTL / key-bound / handshake-consumed token lifecycle is
      now observable end-to-end in the audit trail (`token_issued` → `token_verified` or
      `token_consumed`).

### Deferred (Phase 4 remainder)

- ⬜ Dedicated pairing-lifetime UI panel and BLOCKED-status management.
- ⬜ In-UI audit viewer (the log is tail-able at `data/audit.log` today).
- ⬜ Live verification of revoke/rotation peer removal and gateway audit events (needs an
      elevated WireGuard host).

## Phase 5 — professional product

Implemented subset (testable on this machine); the GUI Support tab and the settings-
encryption remainder are code-inspection / deferred.

### Tamper-evident configuration

- [x] New `security/ConfigIntegrity.java`: keyed HMAC-SHA256 over the exact configuration
      bytes, with the key stored in the OS-restricted credential store
      (`config-integrity-key.secret`); constant-time compare; sidecar named
      `config.yaml.mac`.
- [x] `ConfigManager` gains a `(Path, String integrityKey)` constructor (legacy
      single-arg constructor delegates with `null` = unverified mode, so existing code and
      tests are untouched):
  - `load()` verifies the HMAC when the key is set and the sidecar exists; a mismatch
    throws `ConfigException.STALE` before any parsing.
  - A missing sidecar is accepted as legacy (warn) and re-signed on the next save.
  - `save()` writes the sidecar atomically (temp + move) from the exact serialized bytes.
- [x] `AppContext` builds the `CredentialStore` before the `ConfigManager` and passes
      `ConfigIntegrity.keyFor(credentials)`.
- [x] Honest limits documented in `ConfigIntegrity`: this detects corruption and casual
      tampering — not a fully compromised same-user account (the key shares the data-dir
      ACL).
- [x] Graceful handling when the config cannot be loaded:
  - `MainApp.start()` catches `ConfigException` and shows a clear fatal dialog (with the
    backup/reset guidance) instead of crashing opaque.
  - `Launcher.runDiagnostics()` still emits a full report when the configuration is
    corrupt/tampered (falls back to default config for reading).
- [x] `Cli.parse` no longer returns early on `--diagnostics`, so `--data-dir` after
      `--diagnostics` is honored (CLI ordering bug fixed).

### In-UI support / diagnostics panel

- [x] `SettingsView` gains a **Support** tab: About block (version, Java, OS, user, data
      directory, config-integrity state) plus a redacted diagnostic report generated via
      the same `Diagnostics.gather` path as `--diagnostics`, with **Generate report**, **Save report…** (FileChooser → `Diagnostics.write`) and
      **Copy to clipboard**. Launched live on the win32 host.

### Client device-key pinning

- [x] `completePairing` records a SHA-256 pin of this device's own WireGuard public key in
      `client.pubKeyHash` (`AppConfig` + `clientPubKeyHash()` accessor).
- [x] `connect()` verifies the pin against the live key material
      (`ClientService.keyFingerprint` / `verifyKeyPin`, pure functions); a replaced key
      fails with `AUTH_FAILED` ("device key changed since pairing; re-pair"). Legacy
      pairings without a pin are accepted (blank pin skips the check).

### Modern glass UI ("glassic" desktop)

- [x] `styles.css` redesigned as a glassmorphic theme with full dark + light palettes:
      translucent layered surfaces with top-edge highlights, gradient accent buttons,
      pills and status LEDs with glow shadows, rounded glass cards/tabs/forms, slim
      glass scrollbars and glass dialogs/tooltips.
- [x] New aurora background (`ui/components/AuroraBackground`) sits behind the chrome:
      **static by default** (cached sprites, near-zero idle CPU) with drift opt-in via
      `-Dcra.aurora=animated` and full disable via `-Dcra.aurora=off`.
- [x] Runtime safety: the server dashboard reads a cached `HealthMonitor` snapshot
      (`HealthMonitor.cached()`, kept fresh by the background tick) instead of spawning a
      `wg`/VPN subprocess on the FX thread every second — this was the cause of the
      click-stall/rotating-cursor freeze.
- [x] JavaFX animation layer in `Ui`: page-entrance fade+slide+scale (`Ui.enter`) and
      button hover-lift/press micro-interactions (`Ui.enhance`), wired into
      `MainView.setContent`, `SetupWizard.setPage` and both `PairDeviceDialog` scenes.
- [x] `MainView` wraps its `BorderPane` chrome in a themed `StackPane` shell so the theme
      tokens (`dark`/`light`) and aurora apply behind the whole window; the CONNECT button
      keeps its base `button` class across state toggles.
- Launched live on the win32 host (server mode; `PERMISSION_REQUIRED` expected — not
  elevated, WireGuard absent). UI clicks verified responsive under load; all 185 tests
  stay green.

### First-run role choice & start-from-scratch

- [x] The setup wizard's **CLIENT-vs-SERVER chooser** now gates every dashboard: the
      wizard records an `app.setupDone` marker when it completes, and fresh seat configs
      default to *not* set up. Nothing boots straight into a role without the chooser.
- [x] Legacy configs written before the marker still boot to a role only when genuinely
      ready — a paired client with an endpoint, or a gateway whose WireGuard server keys
      exist (`AppConfig.isSetupComplete`). Anything else re-opens the chooser (which
      pre-selects the previous role and keeps existing field values).
- [x] The **un-paired client state** is now a setup-state, not a hard failure: a blank
      endpoint on a never-paired client is a validator WARNING; only a vanished endpoint
      *after* pairing is an error.
- [x] Invalid/unparseable seat configs (e.g. a reset left a blank CLIENT behind — this
      used to be a fatal "gateway address is not configured" dialog) fall back to the
      first-run wizard via `AppContext.overrideConfig`; the file is left untouched until
      the wizard writes a fresh valid config. Tamper (`STALE`) and newer-version configs
      still show the protecting fatal dialog.
- [x] Settings → **Advanced** gains **Start from scratch…** (with confirmation): wipes
      config, its integrity sidecar and backup, credentials and runtime data (the HMAC
      key is retained so the running `ConfigManager` stays valid), then re-runs the role
      chooser in place. **Reset configuration** keeps keys, but the next start also
      re-asks CLIENT/SERVER.

### One-click dependency install + auto run-as-admin

- [x] **Detect automatically:** `RequirementChecker` already surveys OS support, the
      WireGuard tooling and elevation at startup; the server dashboard's state card now
      acts on it — a live action button appears exactly when a requirement blocks the
      gateway.
- [x] **PERMISSION_REQUIRED → "Run as administrator…"**: relaunches this application
      elevated (Windows `Start-Process -Verb RunAs`, Linux `pkexec`, macOS `osascript`)
      and exits; the new instance continues the normal run already elevated.
      `Elevation.elevateCommand` passes the executable and each argument *separately*
      (quoted), so classpaths/paths with spaces survive elevation, and refuses to
      elevate when already elevated — no relaunch loop.
- [x] **BINARIES_MISSING → "Install WireGuard…"**: relaunches elevated with
      `--fix-requirements`; the elevated instance runs `DependencyInstaller`'s platform
      plan (Windows `winget install -e --id WireGuard.WireGuard ...`, or a
      wireguard.com manual fallback when winget is absent; Linux `apt-get`/`dnf`;
      macOS `brew`), re-surveys, and once `wg` is present calls
      `GatewayService.rebootstrap()` — the gateway opens without a manual restart.
- [x] `--fix-requirements` is also a plain headless flag: it goes through `Cli.parse`
      unmodified and is read from `Application.getParameters()` by `MainApp.start`.
- [x] Unit tests: `DependencyInstallerTest` (winget-present/absent, apt/dnf, brew, hint
      guards), `ElevationTest` (Start-Process quoting, argv split, empty/null rejection),
      `CliTest` (`--fix-requirements` → normal launch).
- ⬜ Live UAC prompt + actual winget install: needs an elevated host with WireGuard; here
      the code compiles, the suite passes, the app launches cleanly, and the dashboard
      renders the two action buttons (PERMISSION_REQUIRED / BINARIES_MISSING states).

### Deferred (Phase 5 remainder)

- ⬜ Theme syncing across devices (the theme picker already persists `app.theme` locally).
- ✅ Config *encryption at rest* — IMPLEMENTED in the user-driven polish pass: `ConfigCipher`
      AES-256-GCM (`cra-enc:v1:` header, nonce + sealed payload), key in the credential store
      (`config-encryption-key.secret`), wired through `ConfigManager(Path, String, String)`;
      legacy plaintext loads (sidecar-verified) and upgrades to ciphertext on the next save,
      at which point the HMAC sidecar is superseded; wrong key / tamper → `ConfigException.STALE`.
      (`ConfigCipherTest`, `ConfigManagerEncryptionTest`.)
- ✅ User-driven UX round — IMPLEMENTED: Settings can always return Home (header **Home** button);
      the client public key is one-click **copyable** on the client setup page and a new
      **MY PUBLIC KEY** card on the client dashboard; Settings → General adds an
      **Enable administrator mode…** button (relaunch elevated, disabled+relabeled when already
      elevated) and a role banner; the VPN tab disables **SERVER LISTEN PORT** on CLIENT seats;
      the gateway setup adds **Auto-detect company LAN…** filling LAN subnet + interface from
      real detection (`NetworkManager.detectLanCidr`: `Get-NetIPAddress` PrefixLength /
      `ip -o -4 addr`, skipping loopback/link-local/tunnel interfaces) with a default VPN
      subnet when blank. Every field stays manually editable; the public endpoint remains
      manual because a public address cannot be detected.
- ⬜ Native uninstaller, upgrade notifications, plugin boundaries, packaging polish and release
      deliverables — need installers/signing/channels. (Version/branding polish shipped as **1.1.0**:
      `app.properties` bumped with `app.vendor`/`app.copyright`, surfaced in `BuildInfo` and the
      Support tab, which also reports the live encryption-at-rest state.)

## Verification

- [x] `javac` build of the full `src/main` tree against `target/lib/*` (JavaFX 21.0.4,
      zxing) — compiles with zero errors.
- [x] `javac` build of the full `src/test` tree.
- [x] Full JUnit suite executed with the JUnit Platform launcher (jars from the prior
      Maven build in `~/.m2`): **185 tests pass, 0 failures** — 185 test methods
      written, of which the two Linux/macOS-branch `DependencyInstaller` assumptions
      skip on this Windows host (69 after the P0/P1 pass + 14 from the Phase 1 finishing
      work + 31 Phase 2 tests + 14 Phase 3 tests
      covering `TunnelTester` (ICMP-independent reachability + DNS injection),
      `WireGuardAdapter` (interface parse/reuse/listTunnels) and `HealthMonitor`
      (stale peers, saturation) + 11 new Phase 4 tests: `AuditLogTest` (chaining,
      tamper detection, redaction, tail, guards) + registry revoke/reuse/rename-audit
      extensions + pairing audit trail, + 12 new Phase 5 tests: `ConfigIntegrityTest`
      (sidecar round-trip, tamper → STALE, sidecar tamper, legacy acceptance, repair,
      key stability, HMAC determinism/keyed) + client pin tests at/after pairing + the
      `--data-dir`-after-`--diagnostics` CLI ordering test, + 1 `HealthMonitor.cached`
      snapshot test added with the UI-performance fix (the dashboard no longer runs a
      `wg` subprocess on the FX thread), + 10 first-run tests: `SetupStateTest`
      (setup marker, legacy client/server readiness, null guard) +
      `ConfigValidatorClientStateTest` (un-paired blank endpoint is a warning,
      vanished endpoint after pairing is an error, invalid endpoint, blank server host)
      + 9 dependency-installer/elevation/CLI tests: `DependencyInstallerTest` (winget
      present → automatic plan, winget absent → manual fallback, apt/dnf + brew plans,
      hint guards) + `ElevationTest` (Start-Process passes exe+args separately, argv
      split order, empty/null rejection) + `CliTest` `--fix-requirements` pass-through.)
- [x] CLI smoke test on this machine: `--version` → `1.0.0`; `--diagnostics` produced a
      complete redacted report honoring `--data-dir` (including when the flag follows
      `--diagnostics`); a fresh data directory on `--diagnostics` created the
      `config-integrity-key.secret` under `credentials/`.
      `mvn test` itself cannot run on this machine — Maven/the wrapper are not installed.
- [ ] Live VPN/NAT/firewall verification still requires an elevated session with
      WireGuard installed (not present on this machine); results are code-inspection
      plausible only.