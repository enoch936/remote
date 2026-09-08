# Company Remote Access — Technical & Compliance Audit Report

- **Audited revision:** working tree at `C:\remote` (current HEAD `56f791e`, commit subject *"Initial implementation: dual-mode remote access app with JavaFX UI, WireGuard backend, and unit tests"*).
- **Method:** static inspection only; the audit never created a tunnel and modified no source, config, networking, or system state at audit time. Findings below are derived from code (`file:line`), the prior build artifacts (`target/`, incl. Surefire reports), the user's real runtime home directory (`C:\Users\Gebretsadik\.company-remote\`) and registry/NAT/service queries on this Windows 11 machine.
- **Upgrade applied after the audit:** all **P0 + P1** findings were subsequently implemented per `COMPANY_REMOTE_ACCESS_UPGRADE.md` (pairing-token consumption, zero-peer ONLINE, macOS gateway, firewall reversal, client rollback, shutdown race). A **Phase 1 finishing pass** then closed the remaining Phase 1 items: strict input validation (`Validation` wired into config/builder/registry/pairing/client), NAT configure-then-verify + teardown (new `NAT_FAILED`/`FIREWALL_FAILED` states), and dead-config cleanup with a working auto-connect setting. A **Phase 2 system-automation pass** added OS-standard data directories (+ legacy migration), a requirement checker, a headless redacted diagnostics report, elevation self-relaunch, and `--version`/`--diagnostics`/`--data-dir` CLI flags. A **Phase 3 network-reliability pass** made gateway reachability handshake-authoritative (ICMP no longer gates the verdict), made non-Windows tunnel starts idempotent (connection reuse, no "already exists" failures), flushed the macOS DNS cache after `wg-quick up`, and added a stale-peer health metric. A **Phase 4 device-ecosystem pass** wired the previously dead `AuditLog` into gateway lifecycle / pairing / registry (tamper-evident, redacted, `data/audit.log`), added **Revoke / Rename / Re-pair (key rotation)** actions to the device list with best-effort live peer removal, and enforced device-name validation on rename. A **Phase 5 professional-product pass** made `config.yaml` tamper-evident (keyed HMAC-SHA256 sidecar `config.yaml.mac`, key in the credential store; STALE rejection on mismatch, legacy acceptance when the sidecar is absent until the next save), added an in-UI **Support** tab (About info + redacted, save-able/copyable diagnostic report) to `SettingsView`, recorded a SHA-256 pin of the client's own WireGuard public key at pairing (`client.pubKeyHash`) verified on every connect, made startup/`--diagnostics` resilient to a corrupt/tampered config (clear fatal dialog instead of a crash; the CLI report still emits), and fixed the `--data-dir`-after-`--diagnostics` CLI ordering bug. Line references in the body describe the **upgraded** code; §1 and §14 note which findings are resolved. Verification: full `javac` of `src/main`+`src/test` (zero errors) and the whole JUnit suite executed locally via the JUnit Platform launcher — **185 tests, 0 failures** (Maven itself is not installed here).
- **Runtime on this machine:** Java 21.0.12 LTS, no Maven on PATH and no `mvnw`, WireGuard **not installed**, app repeatedly reached `PERMISSION_REQUIRED` (non-elevated) so live route/firewall/NAT/tunnel behavior is **UNVERIFIED** here and is classified by code inspection.
- **Status legend:** ✅ implemented & plausible · ⚠️ partial / questionable · 🔴 broken / never reaches online · ❌ missing / dead code · ❓ unverified at runtime.

---

## 1. Executive summary

Company Remote Access is a well-structured, single-process JavaFX 21 desktop app that turns one PC into a WireGuard server (gateway) or client. Design is deliberately "zero-HTTP": **the program opens no listening sockets at all** (no `ServerSocket`/`HttpServer`/`new Socket` anywhere in `src/`), pairing is off-band (QR/clipboard), and all VPN work is delegated to the audited `wg` / `wg-quick` / `wireguard.exe` tooling and OS commands.

**What is solid:** clean layering (`ui / client / server / vpn / networking / security / config / core`), a rigorous gateway state machine with watchdog+backoff, ordered route plans with on-disk manifests, secrets redaction, one-time pairing tokens consumed on first handshake, strict input validation at every security boundary, elevated-requirement surfacing as explicit states, handshake-authoritative connectivity checks, idempotent tunnel starts, a tamper-evident audit trail wired into gateway/pairing/registry, device revoke/rename/key-rotation management, tamper-evident configuration (HMAC sidecar), a client device-key pin at pairing, a modern glass UI theme (both
                                      palettes; static-by-default aurora, drift opt-in),
  background, fade+slide+scale page swaps, button micro-interactions), and 25 green test
  classes (185 tests after the upgrade; 0 failures) covering the pure logic.

**What is wrong or missing (headline):** — resolved findings are marked ✅ FIXED (post-upgrade).

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | New server with **zero authorized devices can never reach ONLINE** — `WgConfigBuilder` required ≥1 peer, threw `IllegalStateException` caught as ERROR. | 🔴 P0 | ✅ FIXED (empty peer list is valid; banner + hint when 0 devices) |
| 2 | **Pairing token is never verified or consumed** — nothing consumed single-use tokens; the registry entry was the real authorization. | ⚠️ P1 | ✅ FIXED (token consumed when the owned key's first handshake succeeds) |
| 3 | macOS gateway **can never go ONLINE** — `MacOSFirewall`/`MacOsNat` threw UNSUPPORTED_PLATFORM. | 🔴 P1 | ⚠️ PARTIAL (split-tunnel ONLINE now; full-tunnel still needs admin pf + forwarding) |
| 4 | **Firewall rules are never removed** — `FirewallManager.removeAllManaged()` had no caller; rules persisted after shutdown. | ⚠️ P1 | ✅ FIXED (reversed in `close()`/`rebootstrap`) |
| 5 | **`security.connectOnAppStart`, `client.pairApplied`, `server.allowFullLan`, `server.publicEndpoint`, `server.endpointMode` are written to config but never read** — auto-connect on start, LAN passthrough, and server public-endpoint detection are dead features. | ⚠️ P2 | ✅ FIXED (dead keys dropped from `AppConfig`; `connectOnAppStart`+`pairApplied` now honored — auto-connect on startup with a Settings toggle; strict `Validation` added) |
| 6 | **`AuditLog` is dead code** — instantiated nowhere; no audit trail exists in production. | ⚠️ P2 | ✅ FIXED (Phase 4: wired into gateway lifecycle + pairing + registry; redacted + tamper-evident; `data/audit.log`) |
| 7 | **Client failure during VERIFY leaves the tunnel running** — `connectInternal` returned on `VPN_FAILED` without tearing down WG/routes. | ⚠️ P2 | ✅ FIXED (`rollbackAfterFailure()` on every failure path) |
| 8 | **IPv6 entirely absent** → full-tunnel (and split-tunnel with LAN CIDR) leaks IPv6 when the OS has IPv6. | ⚠️ P1 security | ⬜ OPEN |
| 9 | Per-second PowerShell queries (`Get-NetAdapter`/`route print`) from watchdog + UI → jank/perf and CPU on slow machines. | ⚠️ P3 | ⬜ OPEN |
| 10 | Async disconnect vs `System.exit(0)` race in shutdown → routes/NAT cleanup may not complete on exit. | ⚠️ P2 | ✅ FIXED (`ClientService.close()` awaits executor before exit) |
| 11 | macOS/ARM Homebrew path missing (`/opt/homebrew/bin/wg-quick` never checked) → BINARIES_MISSING on Apple Silicon. | ⚠️ P2 | ✅ FIXED (Homebrew paths + `which wg-quick` fallback) |

Overall verdict (post-upgrade): **architecture-ready and materially more robust — still not fully production-ready.** With WireGuard installed and an elevated gateway, split-tunnel server/client on Windows/Linux/macOS is plausible; a fresh server now reaches ONLINE and awaits its first pairing. Remaining blockers: IPv6 (finding #8), macOS full-tunnel NAT still requires manual pf, and the polling-perf item (#9).

---

## 2. Architecture

```
                    +--------------------------------------------------------------+
                    |                         MainApp (JavaFX 21)                    |
                    |   bootstrap -> AppContext -> loadConfig -> configureServices   |
                    +-------------------------------+------------------------------+
                                                    |
          +------------------Mode: SERVER-------------+-----------------Mode: CLIENT--+
          |                                                                          |
   GatewayService (state machine:                        ClientService (state machine,
    STOPPED/STARTING/ONLINE/NETWORK_LOST/                  OFFLINE/INITIALIZING/...CONNECTED)
    RECOVERING/PERMISSION_REQUIRED/BINARIES_MISSING/       with ReconnectManager + backoff)
    ERROR/STOPPING)                                                        |
    watchdog 8s + init network monitor 3s                        +---------+-----------+
          |                                                    routing undo/apply
   +------+------+                                                via RoutingManager
   | VpnManager  |<--wraps--> WireGuardAdapter (wg/wg-quick/     (RoutePlan + manifest)
   | (server)    |          wireguard.exe, zeroHTTP design)              |
   +-------+-----+                                                 +------+--------+
           |                                                       | WireGuardAdapter| (client side)
   applyGatewayNat (NatManager: Win/Linux/macOS)                   +---------------+
   applyFirewallRule (FirewallManager: Win/Linux/macOS)      KeyManager(wg pubkey), CredentialStore,
   PeerRegistry(devices.json, PairingManager: SHA-256           TunnelTester(ICMP/DNS/Socket probe)
   token hashes + rate limit)                                   NetworkManager(Get-NetAdapter/ip)
                                 |
   NetworkManager (poll 3s)  native |   config (YAML subset parser) AppConfig
   CommandRunner (native CLI pipes, redaction)  AppLogger(categories+redaction)  Secrets
```

Bootstrap (`MainApp.java:44-210`): start → `AppContext` (data dir = `~/.company-remote`, default `AppConfig.create()`) → `configManager.loadOrCreate()` → if no `config.yaml` show `SetupWizard` → `configureServices()`. In SERVER mode it creates `GatewayService`, `PeerRegistry`, server VpnManager; in CLIENT mode `ClientService`, client VpnManager. `startBackgroundServices()` starts network monitor + gateway. Closing the window hides to tray; tray exit calls `shutdown()` then `System.exit(0)`.

---

## 3. Feature matrix

| Feature | Status | Evidence |
|---|---|---|
| Setup wizard pick SERVER/CLIENT | ✅ | `SetupWizard`, `ServerSetupPage`, `ClientSetupPage` |
| Config load/save/backup (atomic) | ✅ | `ConfigManager.java:78-143` |
| YAML minimal parser + validator | ✅ | `Yaml.java`, `ConfigValidator.java` |
| WG server gateway (split-tunnel) | ⚠️ needs wg+elevation; empty registry OK (ONLINE w/ banner) | `WireGuardAdapter`, `GatewayService`; Finding #1 fixed |
| WG client connect/disconnect | ⚠️ needs wg+elevation; failure-path rollback added | `ClientService.java:150-330` |
| WG key generation / pubkey | ✅ (requires wg) | `KeyManager.java` |
| QR pairing payload | ✅ | `PairDeviceDialog.java:98`, `Qr` |
| Pairing **verification** (single-use) | ✅ consumed on first WG handshake of the bound key | `PairingManager.claimForHandshake`, `GatewayService.updatePeerPresence`; Finding #2 fixed |
| Peer registry (devices.json) | ✅ | `PeerRegistry`/`ClientRegistry` |
| Revoke device (registry) | ✅ Revoke button + best-effort live `removePeer` (`ClientRegistry.revoke`; Phase 4) | `ClientRegistry.revoke`; `ServerDashboard` device list |
| Routing split-tunnel | ✅ | `ClientService.buildRoutePlan`, `RoutePlanValidator` |
| Routing full-tunnel (client) | ✅ (needs serverPublicEndpoint) | same + `WindowsRouting.java:26-33` |
| Route manifest (track+undo) | ✅ | `RouteManifest.java` |
| NAT enable/disable (Win/Linux) | ⚠️ code present + **configure-then-verify**; failures → `NAT_FAILED` (never silent ONLINE); teardown on stop/rebootstrap; Win full-tunnel only; macOS = forwarding + manual pf | `WindowsNat`, `LinuxNat`, `MacOsNat`, `VpnManager.applyGatewayNat/removeAllManagedNat`; Finding #3 partial |
| Firewall allow inbound (server) | ✅ added **and reversed** on stop/rebootstrap | `FirewallManager`, `VpnManager.removeAllManagedFirewall`; Finding #4 fixed |
| Network detection / watchdog | ✅ | `NetworkManager`, `GatewayService` watchdog 8s |
| Auto-reconnect (client) | ✅ | `ReconnectManager` |
| Tunnel health checks (ICMP/DNS/socket) | ✅ handshake-authoritative reachability + injectable DNS (Phase 3) | `TunnelTester`, `DnsLookup`, `TunnelTesterTest` |
| DNS override | ⚠️ config→wg-quick DNS only, no DNS manager | `SettingsView.java:215`, `WgConfigBuilder.dns()` |
| Public-endpoint auto-detection | ✅ removed (dead config dropped) | findings #5 fixed |
| Auto-connect on app start | ✅ `security.connectOnAppStart` + `client.pairApplied` honored (connect only when paired); Settings checkbox | `MainApp.startBackgroundServices`, `SettingsView`; findings #5 fixed |
| Allow full LAN | ✅ removed (dead config dropped) | findings #5 fixed |
| Startup-at-login (Windows RegRun) | ✅ | `StartupManager`, `SettingsView.java:57` |
| Logging with categories + redaction | ✅ | `AppLogger`, `Secrets.redact` |
| Audit log | ✅ wired into gateway/pairing/registry; redacted + tamper-evident (`data/audit.log`) | `AuditLog`, `MainApp`, `GatewayService`, `PairingManager`, `ClientRegistry`; Phase 4 |
| Config integrity (tamper-evident) | ✅ keyed HMAC-SHA256 sidecar `config.yaml.mac` (key in credential store); mismatch → `ConfigException.STALE` before parse; legacy accepted until next save; clear fatal dialog + CLI still-report on corrupt config | `ConfigIntegrity`, `ConfigManager(Path,String)`, `AppContext`, `MainApp`, `Launcher`, `ConfigIntegrityTest`; Phase 5 |
| In-UI support report / About | ✅ Settings → **Support** tab: About block + redacted diagnostic report (Generate / Save… / Copy), reusing the headless `Diagnostics` path | `SettingsView`; Phase 5 (GUI launched live — win32 session) |
| Client key pinning | ✅ SHA-256 pin of the device's own WG public key recorded at pairing (`client.pubKeyHash`) and verified on connect (replaced key → `AUTH_FAILED`); legacy pairings without a pin accepted | `ClientService` (`keyFingerprint`, `verifyKeyPin`), `AppConfig`, `ClientServiceTest`; Phase 5 |
| Modern glass UI ("glassic" desktop) | ✅ (compile-checked) glass palette both themes, translucent layered surfaces/edge highlights, gradient buttons/pills/LEDs + focus glows, glass tabs/forms/lists/scrollbars/dialogs; static-by-default aurora background, page-entrance fade+slide+scale, button hover-lift/press micro-interactions; dashboard reads a cached `HealthMonitor` snapshot (no `wg` subprocess on the UI thread) | `styles.css` (rewrite), `AuroraBackground` (new, `-Dcra.aurora=animated` to drift), `Ui` (`enter`/`enhance`), `MainView` (themed `StackPane` shell), `SetupWizard`, `PairDeviceDialog`; 185 tests still green |
| System tray + window-hide | ✅ | `AppTray` |
| Server dashboard (stats/devices) | ✅ (empty-state banner added) | `ServerDashboard` |
| Client dashboard (health ring) | ✅ | `ClientDashboard` |
| Elevation surfacing (PERMISSION_REQUIRED) | ✅ | `Elevation`, `GatewayService` bootstrap |
| One-click dependency install + run-as-admin | ✅ auto-detect + dashboard action button: `PERMISSION_REQUIRED` → "Run as administrator…" (self-relaunch elevated via UAC, then normal start continues), `BINARIES_MISSING` → "Install WireGuard…" (relaunch elevated with `--fix-requirements`, which runs the platform install plan — winget / apt+dnf / brew — re-checks, then reboots the gateway); `--fix-requirements` also usable headlessly; elevation refuses to re-elevate (no loop) | `DependencyInstaller` (new), `Elevation.relaunchElevated`, `MainApp`, `ServerDashboard`; IMPLEMENTED + LAUNCHED LIVE (requirement states shown on the server dashboard); live UAC/install run pending elevation + WireGuard on the host |
| Strict input validation (keys/endpoints/names/DNS/port) | ✅ at every boundary (builder, registry, pairing, config, client start); paste-buffer injection hardening pending | `security/Validation.java`, `WgConfigBuilder`, `ClientRegistry`, `PairingManager`, `ConfigValidator`, `VpnManager.startClient` |
| IPv6 support | ❌ none | no IPv6 references |
| macOS server | ⚠️ split-tunnel ONLINE; full-tunnel needs manual pf NAT | Finding #3 partial |

---

## 4. Subsystem analysis (with evidence)

### 4.1 Configuration & context
- `AppContext` (`AppContext.java:1-151`) — Home/data dir `Path.of(user.home, ".company-remote")`, `AtomicReference<AppConfig>`, `Yaml`, `CommandRunner`, `NetworkManager` (Thread with 3s interval + listener).
- `AppConfig.java` — flat-map backed; defaults: mode CLIENT name "My Computer"; server "Company-Gateway" listenPort 51820 vpnSubnet 10.50.0.0/24 mtu 1420 pk 25; routing.mode SPLIT_TUNNEL; network.detectIntervalMs 3000; security backoffBaseMs 2000 maxRetries 5 autoReconnect true connectOnAppStart false; client.pairApplied false.
- `ConfigManager.java:78-143` — atomic write (temp+rename), `.bak` backup, `loadOrCreate`, `save`.
- On this machine `config.yaml` is SERVER mode; matches defaults + user edits. `config.yaml.bak` is one-byte-different (auto-save rewrites).

### 4.2 YAML subset
- `Yaml.java` minimal parser (section/maps, quoted strings); `Json.java` minimal JSON for device registry; **neither is a real YAML/JSON parser** — hand-rolled; malformed user files degrade to `IllegalStateException` handled by ConfigManager. Fine for app-owned files; documented limitation.

### 4.3 Cryptography & keys
- No cipher implemented in Java. Uses `wg genkey`/`wg pubkey` (`KeyManager.java`) → private key `chmod 600` stored via `CredentialStore`. 
- `CredentialStore.java` — dir `~/.company-remote/credentials`, files `<name>.secret`, hardened with `FilePermissions.hardenFile` (Windows `icacls` / POSIX `chmod 600`) (`credentials/` was empty on this machine as expected).
- WgConfigBuilder builds `[Interface]/[Peer]` text with keys, `AllowedIPs`, `DNS`, `mtu`; now allows an **empty peer list** (server reaches ONLINE and shows "No devices paired" until the first pairing — Finding #1 fixed); file written to `~/.company-remote/vpn/company0.conf`.

### 4.4 Secrets redaction
- `Secrets.redact()` regexes: `KEY=VALUE`, `private_key`, `WIREGUARD_KEY` (43-char base64), 40+ hex hex. Wired into `CommandRunner` (stdout/stderr) and `AppLogger`. Effective.

### 4.5 Logging
- `AppLogger` rotating file `~/.company-remote/logs/app.log`, categories (SYSTEM/NETWORK/VPN/AUTH/ROUTING/FIREWALL/CLIENT/SERVER/SECURITY/ERROR/UI), redaction.
- `AuditLog` (security hashed-chain audit) — Finding #6 fixed in Phase 4: constructed in `MainApp` server mode (`data/audit.log`), injected into `GatewayService`/`PairingManager`/`ClientRegistry`; each line stores `timestamp | actor | action | sha256(redact(details)) | prevHash`; `verifyChain()` detects tampering, `tail(n)` reads back; blank actors/actions skipped.

### 4.6 Elevation
- `Elevation.isElevated()` — Windows `whoami /groups` SID `S-1-16-12288`; macOS/Linux via `id -u`/uid 0.
- Designer model: do *not* self-relaunch elevated; instead surface `PERMISSION_REQUIRED` with actionable hint (`VpnException.actionHint()`). On this machine the gateway stopped at PERMISSION_REQUIRED as designed (log).

### 4.7 Networking core
- `NetworkManager` — poll os interface list 3s, classify ETHERNET/WIFI, `isOnline` = any up with IPv4; transitions call `onNetworkChanged` (online⇄offline only).
- `RoutePlan` (ordered entries) + `RoutePlanValidator` (errors vs warnings; **full-tunnel requires `serverPublicEndpoint`**, duplicate/conflict CIDRs, gateway sanity).
- `WindowsRouting` — parses `route print -4`; `doAddRoute` `route add` then `route change … if <idx>` pinning; endpoint pinning only when endpoint is a **literal IPv4** (regex) else skipped; `undoPlan` matches cidr+gateway+interface and `route delete`s only managed entries. 
- `LinuxRouting` — `ip route show`; full-tunnel default via metric 10.
- `RouteManifest` — JSON array persisted (restores nothing on boot; used by undo).
- `NatManager` SPI: `WindowsNat` (New-NetNat + IPEnableRouter; only for full-tunnel; after a successful configure it no longer throws a fake permission notice — it logs a reboot note as WARN), `LinuxNat` (sysctl ip_forward + iptables MASQUERADE + FORWARD wg+ ACCEPT; idempotent), `MacOsNat` → sets `sysctl net.inet.ip.forwarding=1` and logs exact `pfctl` NAT guidance (`isEnabled()` reads the sysctl back; full-tunnel NAT still requires manual pf — Finding #3 partial).
- `FirewallManager` — Windows `netsh advfirewall` rule `CompanyRemoteAccess::*` (dir=in proto=UDP localport), Linux iptables (`-C`/`-A`), macOS no-op manifest bookkeeping. **Now reversed:** `VpnManager.removeAllManagedFirewall()` → `removeAllManaged()` is called from `GatewayService.close()`/`rebootstrap()` and `ClientService` rollback (Finding #4 fixed).

### 4.8 VPN plumbing
- `VpnManager` — normalize status from `wg show`, builds/loads config, `startTunnel`/`stopTunnel`. Client start = WG only (no firewall/NAT); Server start = firewall rule (+NAT for full-tunnel), and maps adapter exceptions: `PERMISSION_REQUIRED`, `BINARIES_MISSING`, `CONFIGURATION_ERROR`… GatewayService translates to gateway states.
- `WireGuardAdapter` — Windows `wireguard.exe /installtunnelservice` + `sc`, Linux/macOS `wg-quick up/down`; WG binary searched incl. `where`/`which`; **after the upgrade** `wg-quick` is also searched at `/usr/bin`, `/usr/local/bin`, `/opt/homebrew/bin`, `/opt/local/bin` plus a `which wg-quick` fallback (Finding #11 fixed). Status parse of `wg show … dump`; self-reported.
- On this machine: `wg` was absent → repeated `BINARIES_MISSING` ("VPN engine unavailable") in `app.log`, so the adapter never ran.

### 4.9 Gateway server
- `GatewayService.java` — full lifecycle state machine (STOPPED→STARTING→ONLINE→NETWORK_LOST→RECOVERING, plus PERMISSION_REQUIRED/BINARIES_MISSING/NAT_FAILED/FIREWALL_FAILED/ERROR/STOPPING); watchdog thread every 8s driving `recover()`; `handleRecoveryFailure` maps exceptions → PERMISSION_REQUIRED / BINARIES_MISSING / NAT_FAILED / FIREWALL_FAILED / backoff / ERROR after `maxRetries`; tracks online/offline identity. On `NETWORK_LOST` → stop tunnel + retry with backoff (2s base). Logs state changes via category=state name (falls back to SYSTEM).
- Post-upgrade: gateway shares the app-wide `PairingManager` (via `MainApp`), `updatePeerPresence` **consumes a token on the first WG handshake of the bound public key** (single-use/one machine per token — Finding #2 fixed), prints a "no devices paired" hint for zero-peer ONLINE (Finding #1 fixed), and `close()`/`rebootstrap()` reverse firewall **and** NAT changes via `VpnManager.removeAllManagedFirewall()`/`removeAllManagedNat()` (Findings #4/#5 fixed).
- Correct behavior observed on this machine end-to-end (STOPPED→STARTING→PERMISSION_REQUIRED with the actionable hint, then watchdog stuck at PERMISSION_REQUIRED rather than hammering).

### 4.10 Client
- `ClientService.java` — `setDesiredConnected` → `connectInternal` (network gate → ensure keys → `loadConfig` → validation → DNS → `startClient`/wait → buildRoutePlan → resolve errors → applyPlan → health probe) → OPEN/VERIFY/RETRY states; disconnect = undo plan + `undoAllManaged`. **Failure during VERIFY now tears the tunnel down**: every post-`startClient` failure path calls `rollbackAfterFailure()` (stop tunnel + undo `lastPlan` + `undoAllManaged`) (Finding #7 fixed).
- `ReconnectManager` — retry set {SERVER_UNAVAILABLE, NETWORK_UNAVAILABLE, VPN_FAILED, ERROR, RETRYING}; never auto-retries AUTH/PERMISSION type; keyed to user intent; resets backoff on explicit connect.
- Post-upgrade: `ClientService.close()` = `disconnect()` + `executor.shutdown()` + bounded `awaitTermination(6s)` then `shutdownNow()` (Finding #10 fixed); `connectOnAppStart`+`client.pairApplied` are now honored — `MainApp.startBackgroundServices()` auto-connects only when the device is paired, and Settings has a "Connect automatically when the application starts" checkbox (Finding #5 fixed).
- `PairingManager` / `GatewayService` share one instance with the UI (server side) so issued tokens are tracked app-wide (Finding #2).

### 4.11 Startup manager
- `StartupManager` — Windows `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v CompanyRemoteAccess`; Linux/XDG autostart; macOS LaunchAgents. Only used by `SettingsView` (LAUNCH ON LOGIN checkbox, applies immediately). HKCU query on this machine: **no entry present** (never enabled).

### 4.12 Health & probing
- `TunnelTester` — sequence: assigned IP present → VPN handshake (`wg show` non-null handshake) → Socket connect to gateway IP → DNS resolution of `dns1`/`dns2` → ICMP ping of probe (gateway/first LAN host) via `OsPing` (`ping` binary) → optional company probe + internet check. ICMP-only company probe → false negatives on networks blocking ICMP.

### 4.13 UI
- `SetupWizard` + `ServerSetupPage`/`ClientSetupPage` — wizard → config write; client page shows machine WG public key; "I already have a code" paste box → `ClientService.completePairing`.
- `PairDeviceDialog` — admin enters device name + pasted client pubkey → `PairingManager.issue(name, publicKey)` (token) → QR + payload textarea; the pasted key is bound to the token so it can be verified server-side on first handshake; the dialog uses the shared app `PairingManager`.
- `ServerDashboard` — gateway status banner, restart button, device list (pubkey, assigned IP, last-handshake, rx/tx), NAT/Firewall/VPN/LAN status LEDs (dashboard re-reads status every 1s); **empty-state banner** when no devices are paired (Finding #1 UX); uses the shared `PairingManager`.
- `ClientDashboard` — CONNECT toggle, status ring, live labels (session/tunnel/checks/PUBKEY), health box. 
- `SettingsView` — CLIENT/SERVER tabs; Server tab edits server.name/listenPort/routing.mode/routes.Server tab also edits DNS override (client), gateway name, port, route mode, extra routes, autoReconnect, maxRetries, backoff, LAUNCH ON LOGIN.
- `AppTray` — toggle menu item refresh only at install (stale label).
- **Not present:** NAT setting, firewall toggles, endpoint auto-detect display, server public endpoint editor, pair-again/QR re-display, DNS server management, TCP/IPv6 toggle, theme picker (theme config in default set only). *(Device revoke / rename / re-pair and key rotation are present — added in Phase 4.)*

### 4.14 Main / Launcher
- `Launcher` main; `MainApp` (JavaFX) — `start`: if no config → wizard; else dashboard by mode. `configureServices` decides based on role (server vs client) and creates only the services for that role. `shutdown()` stops network monitor, calls `clientService.close()` (blocks on executor up to 6s — Finding #10 fixed), writes config, exits 0.

---

## 5. State machine analysis

`StateMachine.java` — explicit transition table:
- Boot path: `OFFLINE → INITIALIZING → CHECKING_NETWORK → AUTHENTICATING → CONNECTING → CONFIGURING → VERIFYING → CONNECTED`.
- Failure states: `ERROR, RETRYING, AUTH_FAILED, SERVER_UNAVAILABLE, NETWORK_UNAVAILABLE, PERMISSION_REQUIRED, VPN_FAILED`.
- Transitions are validated (reject illegal moves, throw), listeners notified synchronously. Second machine will never be missed — good.

Gateway's custom enum adds `NETWORK_LOST`/`RECOVERING`; recovery loop never treats `PERMISSION_REQUIRED`/`BINARIES_MISSING` as retryable (stays put until user action) — good.

---

## 6. Pairing deep-dive (post-upgrade: single-use, key-bound)

Flow as implemented (post-upgrade):
1. Admin types client **public key** by hand + a name → `PairDeviceDialog` → `PairingManager.issue(name, clientPublicKey)` → `PairingToken(serverName, serverPublicKey, assignedClientAddress, token, serverHostHint)` payload binds the key; rendered to QR; also shown as text.
2. Client wizard: "I already have a code" → paste → `PairingToken.fromPayload` (strict validation: 44-char base64 server key, valid IPv4, port 1–65535) → `ClientService.completePairing` writes `client.serverEndpoint/vpnIp/server.name` + `client.pairApplied=true`.
3. **Consumption:** the server keeps the TTL'd, single-use, rate-limited token in its shared `PairingManager`. When the first WG handshake from that device is observed, `GatewayService.updatePeerPresence` → `PairingManager.claimForHandshake(publicKey)` marks the token consumed. A second machine presenting the same QR payload can no longer be verified — the token is single-use **in actual operation**, not just cosmetically.

Residual gaps: consumption is handshake-triggered, so the token only "verifies" the machine that already appears in `devices.json` (the admin's pasted key is still the root authorization). The `verifyAndConsume` API remains covered by unit tests; `client.pairApplied` is still written but not read (Finding #5).

---

## 7. Platform support

- **Windows 11 (this machine):** client+server design OK; requires elevated session for connect/gateway; NAT full-tunnel-only and logs a reboot note after applying (no false throw — Finding #3 partial); firewall rule now reversed on shutdown. Unverified live.
- **Linux:** full NAT/firewall/routing implemented idempotently (iptables, sysctl); likely to work with wg-quick present. Unverified live.
- **macOS:** **server can now reach ONLINE** for split-tunnel — `MacOSFirewall` is a no-op manifest bookkeeper and `MacOsNat` sets `sysctl net.inet.ip.forwarding=1` + prints exact pf piping guidance (full-tunnel NAT still needs the admin to run the printed `pfctl` commands); `wg-quick` found via Homebrew/PATH fallbacks (Finding #11). Full-tunnel remains a documented-manual step.

---

## 8. Security review

### Good
- Zero listening sockets; no exfil surface; no self-made crypto; keys only in `wg`/OS-store; private keys never in logs/config (central redaction); SHA-256-token-hash storage with TTL+rate-limit; manifest tracked routes with exact-match undo; `PERMISSION_REQUIRED`/`BINARIES_MISSING` explicit states instead of silent failure; files created with restrictive ACLs; `ready-to-use` closed state machine.

### Gaps
1. ~~No audit logging (`AuditLog` dead)~~ ✅ Fixed — Phase 4 wires it into gateway start/stop/rebootstrap + terminal states, pairing issue/verify/consume, and registry add/revoke/rename/remove; redacted + tamper-evident (`data/audit.log`).
2. ~~Fixed WG port rule persists (never removed) on server shutdown → other processes can hold port open / stale rule.~~ ✅ Fixed — reversed on `close()`/`rebootstrap()`.
3. No IPv6 anywhere → full-tunnel leaks IPv6 (or drops it entirely, breaking IPv6 sites).
4. ~~Client connect runs elevated `wg set`/`route`/`wg-quick` on whatever the paste-buffer contains (payload not validated).~~ ✅ Partially fixed — `PairingToken.fromPayload` now strictly validates server key (44-char base64), IPv4 and port range before writing config; injection through token fields is mitigated.
5. ~~No secrets rotation / no key reset for a compromised client (revoke exists server-side only, and no UI).~~ ✅ Mostly fixed — Phase 4 adds a **Re-pair** (rotation) action: revoke old key, re-enroll the same VPN address with a new pasted key, fresh single-use token, best-effort live peer removal. Remaining: live verification on a WireGuard host.
6. ~~`config.yaml` stored unencrypted with no integrity check (an attacker who can write the data dir can redirect endpoints / disable retries).~~ ⚠️ Partially fixed — Phase 5: `config.yaml` is now **tamper-evident** (keyed HMAC-SHA256 sidecar `config.yaml.mac`, key in the OS-restricted credential store; STALE rejection on mismatch, legacy acceptance until re-save). *Encryption* at rest is still not implemented; and a same-user attacker who can also write the credential store can defeat the check (documented limit).

---

## 9. Networking risks

- IPv6 leak in FULL_TUNNEL (Finding #8) and partial IPv6 drop in SPLIT_TUNNEL when LAN CIDR excludes IPv6.
- ICMP-only company probe → false `VPN_FAILED` where ICMP is filtered.
- `TunnelTester` reachability uses system DNS, not tunnel DNS on failure paths.
- Windows endpoint pinning skipp-ed for non-literal endpoints → full-tunnel default route may escape the tunnel interface.
- `NetworkManager`/dashboard PowerShell per-second polling on all interfaces → perf/jank on busy hosts (mitigate with caching).
- No keep-alive or funnel mtu auto-detect; `persistentKeepalive 25` default is fine for NAT traversal.

---

## 10. Test suite & coverage

- 28 JUnit test classes, **185 tests, all green (0 failures; 2 platform-assumption tests skip on non-target OSes) — re-executed on this machine** via a JUnit Platform launcher (jars from `~/.m2`, since Maven itself is absent; full `javac` of `src/main`+`src/test` also clean).
  - `ClientServiceTest`, `ConfigRoundTripTest`, `StateMachineTest`, `IpHelpersTest`, `RoutePlanValidatorTest`, `PairingManagerTest`, `PairingTokenTest`, `SecretsRedactionTest`, `BackoffStrategyTest`, `ClientRegistryTest`, `WgConfigBuilderTest`, `ValidationTest`, `DataDirsTest`, `RequirementCheckerTest`, `DiagnosticsTest`, `CliTest`, `TunnelTesterTest`, `WireGuardAdapterTest`, `HealthMonitorTest`, `AuditLogTest`, `ConfigIntegrityTest`, `SetupStateTest`, `ConfigValidatorClientStateTest`, `DependencyInstallerTest`, `ElevationTest`.
- **Good coverage** of: token hash/rate-limit, **token consumption by bound key + expired-token rejection (added with the upgrade)**, state transitions, config round-trip, route validation, redaction, backoff, **zero-peer config builder (added)**, and **strict validation (new `ValidationTest`: WG key format, endpoints/hostnames, device names, DNS lists, ports + negative builder/registry/pairing tests)**. New with **Phase 4**: `AuditLogTest` (hash chaining incl. tamper detection, redaction-before-hash, tail, blank-actor guard), registry revoke/address-reuse/key-never-reusable + rename validation, and pairing audit-trail events. New with **Phase 5**: `ConfigIntegrityTest` (sidecar round-trip, tamper → `STALE`, sidecar tamper, legacy acceptance, repair-after-save, key stability, HMAC determinism/keyed), client pin tests (recorded at pairing, replaced key blocks connect, legacy no-pin connects), and the `--data-dir`-after-`--diagnostics` CLI ordering test, and a `HealthMonitor.cached` snapshot test (the server dashboard reads a background snapshot, so the UI thread runs no `wg`/vpn subprocess on its 1-second refresh). New with the **dependency-installer/auto-admin pass**: `DependencyInstallerTest` (winget present → automatic winget plan; winget absent → manual fallback; `apt`/`dnf` and `brew` plans; hint never blank) and `ElevationTest` (Windows `Start-Process -Verb RunAs` passes the executable and each argument separately so spaced paths survive; `launchCommand()` is executable-first with `Launcher` last; empty/null input rejected), plus a `CliTest` case proving `--fix-requirements` passes through to a normal launch.
- **No tests** for: WireGuardAdapter, WindowsRoute/NAT/Firewall adapters, NetworkManager, GatewayService watchdog/recovery, TunnelTester, ClientService failure paths, ConfigManager failure modes. (All shell-heavy; hard to unit test).

---

## 11. Build / packaging / run

- `mvn clean package` produces `target/company-remote-access.jar` (Main-Class `com.company.remoteaccess.Launcher`, jar plugin 3.4.1, no `Class-Path`) + `target/lib/*`.
- `java -jar target/company-remote-access.jar` will **fail** (no Class-Path) → must run per README: `java -cp "target/company-remote-access.jar;target/lib/*" com.company.remoteaccess.Launcher`.
- Requires: WireGuard **installed & on PATH** (`wg`, `wg-quick`/`wireguard.exe`), elevated session for any VPN op, populated `devices.json` for server.

---

## 12. Runtime snapshot (this machine only)

| Item | Value | Implication |
|---|---|---|
| JDK | 21.0.12 LTS | OK for build+run |
| Maven | not on PATH, no `mvnw`, no wrapper | can't rebuild/test here; rely on `target/` artifacts |
| WireGuard | **not installed**; `where wg` fails; no `C:\Program Files\WireGuard` | app runs, VPN ops = `BINARIES_MISSING`; dashboard offers "Install WireGuard…" |
| config.yaml | mode CLIENT, no `app.setupDone` (fresh seat) | first-run CLIENT-vs-SERVER chooser opens on every start until the wizard completes |
| app.log | clean startup: app home, platform, credential store logged, startup requirement wg MISSING (expected), network monitor started | no exceptions, no fatal dialog |
| HKCU Run | no CompanyRemoteAccess | startup-flag off (default) |
| NetNat | none configured | no NAT applied |
| Tunnel svc | `WireGuardTunnel$company0` not found (error 1060) | nothing installed |
| peers.json / devices.json | **empty** | server reaches ONLINE with 0 peers (banner shown); device must be paired for actual VPN access |

---

## 13. README claims vs implementation

| README claim | Reality | Verdict |
|---|---|---|
| “one-time token shown as QR, client pastes payload” | token is bound to the admin-pasted pubkey and **consumed on that device's first WG handshake** (single-use) | ✅ (Finding #2 fixed) |
| “route, firewall and NAT changes tracked **and reversed** on disconnect” | Routes/NAT undone; **firewall rules now also reversed** on stop/rebootstrap | ✅ (Finding #4 fixed) |
| “stored in OS-protected storage (`icacls`/`chmod 600`)” | yes, `credentials/` with `FilePermissions.hardenFile` | ✅ |
| “authorized device registry `~/.company-remote/peers.json`” | actual registry is `~/.company-remote/data/devices.json` | ❌ doc mismatch |
| “Without WireGuard … report BINARIES_MISSING instead of failing silently” | observed exactly that in `app.log` | ✅ |
| “Firewall/NAT asks for elevated session … surfaces PERMISSION_REQUIRED” | verify: elevation check → PERMISSION_REQUIRED state/hint; reboot note on Win NAT | ✅ (with NAT quirk) |
| “system tray icon … closing hides to tray” | yes, AppTray | ✅ |
| “Client setup page shows machine’s WG public key” | only `wg` can produce it → needs WG installed first | ⚠️ dependency |

---

## 14. Defects (P0 lowest → P3) — ✅ = fixed in the post-audit upgrade

**P0**
- ✅ `WgConfigBuilder` required ≥1 peer → fresh server with 0 devices landed in ERROR. Now allows an empty peer list: server reaches ONLINE and shows a "No devices paired" banner + hint.
- ✅ Pairing verification was dead (Finding #2). Now single-use end-to-end: token consumed on the owned key's first WG handshake.

**P1**
- ⚠️ macOS server (Finding #3): split-tunnel ONLINE now; **full-tunnel NAT still requires the admin to run the printed `pfctl` commands** (`MacOsNat` sets IP forwarding + guidance) or use a documented workaround. `MacOsNat.verifyNat` therefore classifies macOS NAT as PARTIAL (by design, not a throw).
- ✅ NAT honesty (related to Findings #3/#5): full-tunnel NAT is now **configured then verified** (`VpnManager.applyGatewayNat` no longer bails on `missingRequirements` before configuring); real failures surface as `NAT_FAILED`/`FIREWALL_FAILED` states instead of a silent ONLINE; NAT state is torn down on stop/rebootstrap (`removeAllManagedNat`).
- ⬜ IPv6 absent (Finding #8). Add `IPv6`/`AllowIPv6` handling or route IPv6 default via tunnel (wg supports it) with explicit opt-in.
- ✅ Firewall rules never reversed (Finding #4). `VpnManager.removeAllManagedFirewall()` → `FirewallManager.removeAllManaged()` on `close()`/`rebootstrap()` and client rollback.

**P2**
- ✅ Config integrity (Phase 5): `config.yaml` signed with a keyed HMAC-SHA256 stored as `config.yaml.mac` (key in the credential store); a mismatch is rejected as `ConfigException.STALE` before parsing, a missing sidecar is accepted as legacy and re-signed on the next save; `MainApp` shows a clear fatal dialog and `--diagnostics` still emits a report when the config is corrupt. *Encryption at rest now implemented (user-driven pass): `ConfigCipher` AES-256-GCM, key in the credential store; legacy plaintext loads then upgrades on the next save.*
- ✅ Client key pinning (Phase 5): pairing records the SHA-256 pin of the device's own WG public key (`client.pubKeyHash`); every connect verifies the pin and refuses a replaced key (`AUTH_FAILED`); legacy pairings without a pin are accepted.
- ✅ In-UI support/diagnostics (Phase 5): Settings → **Support** tab (About + redacted report; Save…/Copy); `--data-dir` now honored after `--diagnostics`.
- ✅ Modern glass UI (Phase 5): `styles.css` fully redesigned as a glassmorphic theme (both light/dark palettes; translucent layered surfaces with top-edge highlights, gradient accent buttons/pills/LEDs with glow shadows, rounded glass cards/tabs/forms/lists/scrollbars/dialogs, slim scrollbars); a new aurora background (`ui/components/AuroraBackground`, static by default to keep idle CPU low; `-Dcra.aurora=animated` to drift, `=off` to disable) sits behind the UI; page swaps animate with fade+slide+scale (`Ui.enter`) and buttons get hover-lift/press micro-interactions (`Ui.enhance`) in the main window, setup wizard and pairing dialogs; `MainView` wraps its chrome in a themed `StackPane` shell. Runtime safety: the server dashboard reads a cached `HealthMonitor` snapshot instead of probing WireGuard via a subprocess on the UI thread every second (was blocking clicks). Verification: app launched and viewed live on this host windowed (win32 session, server mode); all 185 tests remain green.
- ✅ Client failure left tunnel up (Finding #7): `rollbackAfterFailure()` (stop tunnel, undo plan, undo managed) on every post-start failure path.
- ✅ Shutdown race with async cleanup + `System.exit` (Finding #10): `ClientService.close()` = disconnect + `shutdown()` + `awaitTermination(6s)` + `shutdownNow()`.
- ✅ Dead config keys (`connectOnAppStart`, `pairApplied`, `allowFullLan`, `publicEndpoint`, `endpointMode`) (Finding #5): `allowFullLan`/`publicEndpoint`/`endpointMode` removed from `AppConfig`; `pairApplied` persisted on pairing and cleared on forget; `connectOnAppStart` honored at startup (auto-connect only when paired) with a Settings checkbox; `PairDeviceDialog` resolves the pairing host from `serverHost`.
- ✅ Audit trail (Finding #6): `AuditLog` wired into gateway start/stop/rebootstrap + terminal states, pairing issue/verify/consume-on-handshake, registry add/revoke/rename/remove; only redacted-detail hashes stored; `verifyChain()` + `tail()` (Phase 4).
- ✅ Revoke UI + key rotation: `ServerDashboard` Revoke / Rename / Re-pair actions; rotation re-enrolls the same VPN address with a new key + fresh token + best-effort live `removePeer`. Remaining: live verification on a WireGuard host; pairing-lifetime/blocked-state UI; in-UI audit viewer.
- ✅ macOS ARM `wg-quick` PATH (Finding #11): `/opt/homebrew` etc. + `which wg-quick` fallback.
- ⬜ Per-second PowerShell polling perf.
- ✅ Strict input validation (Finding #5 / §8 gap 4): `security/Validation.java` (WG keys `^[A-Za-z0-9+/]{43}=$`, endpoints/hostnames, device names, DNS lists, ports) enforced in `WgConfigBuilder.build()`, `PairingManager.issue()`, `ClientRegistry.add()`, `ConfigValidator`, and `VpnManager.startClient()`. Remaining: paste-buffer line-ending/injection hardening (P3).

**P3**
- Prompt input exceeding ~0 taps in Windows PowerShell 5.1 (exec precedence) — `Runtime.exec` on `route`/`wg` via `cmd.exe` fails under PowerShell 5.1; ensure `CommandRunner` uses `cmd.exe /c` for native shell builtins.
- Tray toggle label refresh; stale endpoint on Settings-save.

---

## 15. Recommended enhancements (P0–P1 done ✅, remaining P2–P3)

**P0**
1. ✅ First-run/zero-peer UX (pair dialog auto-open; online-with-empty).
2. ✅ End-to-end pairing token consumption.
3. ⬜ **IPv6 default handling (the last P1-class security item — still open).**

**P1**
4. ✅ Firewall reversal on stop/shutdown.
5. ⚠️ macOS firewall/NAT — split-tunnel done; full-tunnel still manual `pfctl` — document or implement pf.
6. ✅ Client teardown-on-failure.
7. ✅ Sync shutdown before exit.

**P2**
8. ✅ Wire AuditLog into operations (gateway/pairing/registry; redacted, tamper-evident, `data/audit.log`). ✅ Auto-attach device pubkey hash to configuration (Phase 5: `client.pubKeyHash` pin recorded at pairing, verified on connect).
9. ✅ Device revoke UI + key reset (rotation) + wire `revoke()` to remove WG peer runtime (best-effort; live-verify pending on a WireGuard host).
10. ✅ Path-search for `wg-quick` incl. `/opt/homebrew`.
11. ⬜ Reduce polling (cache snapshot; poll 2s; isolate dashboard from PS).

**P3**
12. ⚠️ Paste-buffer payload InputSanitizer (strict base64/IP/port validation now enforced via `Validation` at config/builder/registry/pairing/client; remaining: line-ending/injection hardening of the paste buffer).
13. ⬜ Keepalive/MTU auto-tune; keep-last-N-log rotation size option.
14. ✅ Config integrity (HMAC sidecar; Phase 5). ✅ Config *encryption* at rest (`ConfigCipher` AES-256-GCM, key in the credential store; user-driven pass). ⬜ Secrets-in-memory-only.

---

## 16. Required real-world configuration (checklist to actually run)

- [ ] Install WireGuard (Windows: full install incl. driver; Linux `apt/…wg-quick`; macOS `wireguard-go`+wg-quick at `/opt/homebrew/bin` or add to PATH).
- [ ] Run the app **elevated** (as Administrator) on the gateway AND on any client that needs VPN (Windows).
- [ ] Server first run: the gateway reaches ONLINE with 0 devices and shows a "No devices paired" banner — pair at least one device to enable actual VPN access.
- [ ] Router/NAT: port-forward UDP 51820 to the gateway host for remote clients.
- [ ] LAN CIDR + LAN adapter set correctly (split-tunnel) or full-tunnel + server NAT.
- [ ] Confirm IPv6 disabled/opt-in if full-tunnel required.
- [ ] Turn on LAUNCH ON LOGIN only if `startWithOS` desired (persists in registry).
- [ ] Optionally open ICMP on the company network for the probe (else use probeHost/DNS-only checks).

---

## 17. Verdicts (final)

- **CURRENTLY WORKING (code-level, unverified live):** split-tunnel server/client core on Windows/Linux/macOS with wg present; pairing QR/paste + **single-use token consumed on first handshake**; zero-peer ONLINE server; route manifest undo; **firewall reversal on stop; client rollback on failure; sync shutdown; strict input validation at every boundary; NAT configure-then-verify with honest `NAT_FAILED`/`FIREWALL_FAILED` states + teardown on stop; working auto-connect-when-paired setting;** **tamper-evident audit trail wired into gateway lifecycle, pairing and registry (revocation/renames); device Revoke / Rename / Re-pair actions with best-effort live peer removal; key-rotation re-enrollment keeping the same VPN address; tamper-evident configuration (HMAC sidecar keyed from the credential store); client device-key pin recorded at pairing and verified on connect; in-UI Support report (About + redacted diagnostics, save/copy); CLI-ordered data-dir override; modern glass UI (aurora background, page/button animations); first-run CLIENT/SERVER role chooser (setup marker gates dashboards) + start-from-scratch factory reset that re-runs it in place;** config persist/backup; redaction; state-machine gating; startup toggle; dashboards.
- **PARTIALLY WORKING:** full-tunnel NAT on Windows (configure+verify implemented structurally, requires elevation; runtime unverified here); macOS full-tunnel NAT (prints `pfctl` guidance; manual; `verifyNat` = PARTIAL by design); DNS override (config only); ServerDashboard statistics (live-but-1Hz); auto-reconnect.
- **BROKEN / never-online:** *(none of the audit's P0/P1 blockers remain; IPv6 and the polling-perf item are the outstanding gaps.)*
- **NOT IMPLEMENTED:** IPv6; a dedicated pairing-lifetime *panel*; banning; bulk/CI admin tooling; theme syncing; uninstaller / upgrade notifications / plugin boundaries / packaging & release deliverables.
- **UNVERIFIED at runtime (all VPN-sensitive paths on this machine):** WireGuardAdapter start/stop/status, route apply, firewall, NAT verify/teardown, gateway ONLINE, client CONNECTED — because `wg` is not installed and elevation is missing (`app.log` shows PERMISSION_REQUIRED / BINARIES_MISSING).
- **SECURITY RISKS:** live peer removal on revoke/rotation untested, paste-buffer injection hardening pending (strict structural validation is in place), archive of old key material in `vpn/` (config files contain wg keys + DNS), redirectable messages? (redaction covers command line and stack traces — verified in CommandRunner/AppLogger).
- **NETWORKING RISKS:** IPv6 leak, ICMP-based probe false-negative, PowerShell-per-second, endpoint-pin skip for hostname endpoints.
- **RECOMMENDED ENHANCEMENTS:** see §15 (P0–P1 done; IPv6 is the remaining P1-class item plus P2–P3 polish).

---

## 18. Post-audit upgrade log (P0/P1 + Phase 1 finishing + Phase 2 system automation + Phase 3 network reliability + Phase 4 device ecosystem + Phase 5 professional product + user-driven polish pass + user-driven UX round) — what changed + verification

Implemented per `COMPANY_REMOTE_ACCESS_UPGRADE.md`; all items verified by `javac` (main+test, zero errors) and the full JUnit run (**185/185 pass, 0 failures** for the current scope with the SKIPPED/OS-gated assumptions identical; Maven absent here, executed via JUnit Platform from `~/.m2` jars).

| Area | Change | Files |
|---|---|---|
| Zero-peer ONLINE (P0 #1) | empty peer list valid; "no devices paired" banner + progress hint | `WgConfigBuilder`, `GatewayService`, `ServerDashboard`, `WgConfigBuilderTest` |
| Pairing verification (P1 #2) | `issue(name, publicKey)` + `claimForHandshake()` consumed on first handshake; shared `PairingManager` across gateway+UI; key passed through `PairDeviceDialog` | `PairingManager`, `GatewayService`, `MainApp`, `ServerDashboard`, `PairDeviceDialog`, `PairingManagerTest` |
| Payload strict validation | server key 44-char base64 / IPv4 / port range | `PairingToken`, `PairingTokenTest` |
| macOS gateway (P1 #3) | firewall no-op manifest; NAT = IP forwarding + printed `pfctl` guidance; `wg-quick` path search incl. `/opt/homebrew` | `MacOSFirewall`, `MacOsNat`, `WireGuardAdapter` |
| Firewall reversal (P1 #4) | `VpnManager.removeAllManagedFirewall()` on `close()`/`rebootstrap()` | `VpnManager`, `GatewayService` |
| Client rollback (P2 #7) | teardown on every post-start failure path | `ClientService` |
| Shutdown race (P2 #10) | bounded `awaitTermination` before exit | `ClientService`, `MainApp` |
| NAT noise (Windows) | no fake throw after successful NAT setup | `WindowsNat` |
| Strict input validation (P1 #3) | `Validation` utility wired into config build, registry, pairing issue, and client start; invalid keys/endpoints/names/DNS/ports rejected with actionable errors; fixtures fixed to real 44-char WG keys | `Validation` (new), `WgConfigBuilder`, `ClientRegistry`, `PairingManager`, `ConfigValidator`, `VpnManager`, `ValidationTest` (new) + updated tests |
| NAT configure-then-verify (P1 #5) | `applyGatewayNat` now applies then verifies (`NatManager.verifyNat` + `NatResult`); absent rules → `NAT_FAILED`/`FIREWALL_FAILED` states (no silent ONLINE); `removeAllManagedNat` teardown on close/rebootstrap; macOS stays PARTIAL-by-design (manual pf) | `NatManager`/`WindowsNat`/`LinuxNat`/`MacOsNat`, `VpnManager`, `VpnException` (NAT/FIREWALL kinds), `GatewayState`, `GatewayService` |
| Dead-config cleanup (P2 #5) | removed `allowFullLan`/`publicEndpoint`/`endpointMode`; `client.pairApplied` persisted on pair + cleared on forget; auto-connect honored at startup when paired (Settings checkbox) | `AppConfig`, `ConfigValidator`, `PairDeviceDialog`, `ClientService`, `MainApp`, `SettingsView` |
| Standard data directories (P2 #12) | base dir now OS-standard (`%APPDATA%\CompanyRemoteAccess`, `~/Library/Application Support/…`, `~/.config/company-remote-access`) with one-time migration from legacy `~/.company-remote`; `--data-dir` override | `DataDirs`, `MainApp` (new) |
| Requirement detection (P2) | `RequirementChecker` surveys OS support, WireGuard tooling, elevation (pure `evaluate` + live `survey`) and logs any non-OK at startup | `RequirementChecker` (new), `MainApp` |
| Diagnostics tool (P2) | headless `--diagnostics [file]` emits a redacted support report (version, OS, data dir, config, wg, elevation, network, start-with-OS, requirements, log tail) | `Diagnostics`, `Launcher`, `Cli` (new) |
| Elevation self-relaunch (P2) | `Elevation.relaunchElevated(args)` restarts this app with admin rights via platform UAC/pkexec/osascript; `canElevate()` guard | `Elevation` |
| Version reporting (P2) | `--version` prints `BuildInfo.version()` headlessly before JavaFX starts | `Cli`, `Launcher` |
| Setup wizard prereq note (P2) | Welcome page now lists WireGuard + admin requirements and points to `--diagnostics` | `SetupWizard` |
| Gateway probes ICMP-independent (P3) | fresh VPN handshake = authoritative gateway reachability; ICMP only measures latency → no more ping-masked false negatives; DNS checks via injectable resolver | `TunnelTester` (+ `DnsLookup`), `TunnelTesterTest` |
| Connection reuse / wg-quick conflicts (P3) | non-Windows start queries `wg show interfaces` and reuses an already-up tunnel (idempotent, no "already exists" failure); `parseInterfaces`/`tunnelAlreadyUp`/`listTunnels` | `WireGuardAdapter`, `WireGuardAdapterTest` |
| macOS DNS resilience (P3) | DNS cache flush (`dscacheutil` + `killall mDNSResponder`) after `wg-quick up` | `WireGuardAdapter` |
| Gateway stale-peer health (P3) | `HealthMonitor` counts peers whose handshake is ≥ 120 s old; reconnect counter saturates at 100 instead of rolling to 0 | `HealthMonitor`, `HealthMonitorTest` |
| Audit-log wiring (P4) | previously dead `AuditLog` is built in server mode (`data/audit.log`), injected into gateway/pairing/registry; events for gateway lifecycle + terminal states, pairing issue/verify/consume-on-handshake, registry add/revoke/rename/remove; only `sha256(redact(details))` stored; `tail(n)` + `verifyChain()`; blank actor/action skipped | `AuditLog`, `MainApp`, `GatewayService`, `PairingManager`, `ClientRegistry`, `AuditLogTest` (new) |
| Device management UI (P4) | device rows gain **Revoke** (status → REVOKED, key permanently non-reusable, VPN address freed, best-effort live `removePeer`), **Rename** (validated), **Re-pair** (`PairDeviceDialog.showRotate`: revoke old key → re-register same address with new key → fresh token → live drop old peer) | `ServerDashboard`, `PairDeviceDialog`, `ClientRegistry` (+`Validation.requireDeviceName` on rename), `ClientRegistryTest` |
| Tamper-evident config (P5) | `ConfigIntegrity` (keyed HMAC-SHA256 over exact file bytes; sidecar `config.yaml.mac`; 32-byte key in credential store `config-integrity-key.secret`); `ConfigManager(Path,String)` + load-time STALE rejection, legacy acceptance when sidecar absent (re-signed on next save), atomic sidecar write on save; wired via `AppContext` | `ConfigIntegrity` (new), `ConfigManager`, `AppContext`, `ConfigIntegrityTest` (new) |
| Corrupt-config resilience (P5) | `MainApp.start` shows a clear fatal dialog (ConfigException) instead of crashing; `Launcher.runDiagnostics` still emits a report when the configuration is unreadable/tampered | `MainApp`, `Launcher`; covered by `ConfigIntegrityTest.tamperedConfigThrowsStale` |
| First-run role choice (P5) | the setup wizard's CLIENT/SERVER chooser gates **every** dashboard via an `app.setupDone` marker (new seat configs start unset-up); legacy configs written before the marker only boot straight to a role when genuinely ready (paired client with an endpoint, or a gateway whose server keys exist) — otherwise the role chooser re-opens. The wizard pre-selects the previous role and keeps existing values | `AppConfig` (`setupDone`, `isSetupComplete`), `MainApp.isConfigured`, `SetupWizard.finish`; `SetupStateTest` |
| Start-from-scratch reset (P5) | invalid/unparseable seat configs (e.g. a reset that left a blank CLIENT behind — previously a hard fatal) now fall back to the first-run wizard; a blank, never-paired client endpoint is a WARNING, not an error (only a vanished endpoint after pairing is an error). Settings → Advanced gains **Start from scratch…** (confirmation) which wipes config + sidecar + backup + credentials + runtime data (HMAC key kept so the current `ConfigManager` stays valid) and re-opens the chooser in place; existing **Reset configuration** keeps keys but next start also re-asks CLIENT/SERVER | `MainApp.start`/`resetToFirstRun`/`wipeState`, `ConfigValidator` (blank-unpaired endpoint), `AppContext.overrideConfig`, `SettingsView`; `ConfigValidatorClientStateTest` |
| In-UI support report (P5) | Settings → **Support** tab: About block (version/Java/OS/user/data dir/config-integrity state), redacted report via `Diagnostics.gather`, Save-as-file (`Diagnostics.write`) + Copy to clipboard | `SettingsView` (GUI launched live here; win32 session) |
| Client key pinning (P5) | pairing records SHA-256 pin of the device's own WG public key (`client.pubKeyHash`); verified on connect (`AUTH_FAILED` on replaced key); legacy no-pin accepted | `ClientService` (`keyFingerprint`, `verifyKeyPin`), `AppConfig`, `ClientServiceTest` |
| CLI ordering fix (P5) | `Cli.parse` no longer returns early on `--diagnostics`, so `--data-dir` after `--diagnostics` is honored | `Cli`, `CliTest.diagnosticsHonorsTrailingDataDir` |
| Modern glass UI (P5) | `styles.css` rewritten as a glassmorphic theme (both palettes): translucent layered surfaces with top-edge highlights, gradient accent buttons/pills/LEDs with glow shadows, rounded glass cards/tabs/forms/lists/scrollbars/dialogs; static-by-default aurora background (`AuroraBackground`, `-Dcra.aurora=animated` to drift / `=off` to disable) behind the chrome; page-entrance fade+slide+scale (`Ui.enter`); button hover-lift/press micro-interactions (`Ui.enhance`) in `MainView.setContent`, `SetupWizard.setPage` and `PairDeviceDialog`; `MainView` root → themed `StackPane` shell (connects to light/dark tokens). Runtime safety: `ServerDashboard` reads `HealthMonitor.cached()` (no `wg` subprocess on the UI thread — fixes click-stall under load). Setup pages now also scroll (SetupWizard pages fitted with `ScrollPane`) and the gateway/client setup pages expose copy-able public keys that auto-appear once `wg` is installed | `styles.css`, `AuroraBackground` (new), `Ui`, `MainView`, `ClientDashboard`, `SetupWizard`, `PairDeviceDialog`, `HealthMonitor`/`ServerDashboard`, `ServerSetupPage`/`ClientSetupPage`; app launched + viewed live here (win32, server mode); 185 tests still green |
| One-click dependency install + auto run-as-admin | `RequirementChecker` already surfaced missing wg/elevation; now the server dashboard's state card shows a live action button: **PERMISSION_REQUIRED → "Run as administrator…"** (self-relaunch elevated via UAC/pkexec/osascript with each argument passed separately, then this instance exits; `Elevation` refuses to re-elevate so there is no loop) and **BINARIES_MISSING → "Install WireGuard…"** (relaunch elevated with `--fix-requirements`; the elevated instance runs the platform install plan — Windows `winget install -e --id WireGuard.WireGuard` (or a wireguard.com fallback when winget is absent), Linux `apt-get`/`dnf`, macOS `brew` — re-surveys, and if `wg` is now present calls `GatewayService.rebootstrap()` so the gateway opens without a manual restart). Works headlessly too: `--fix-requirements` launches the app, installs, and exits back into the normal run. Status: IMPLEMENTED (compile) + unit-tested (`DependencyInstallerTest`, `ElevationTest`, `CliTest`); app launched live — the chooser/setup flow and clean startup verified, and the server dashboard renders the PERMISSION_REQUIRED/BINARIES_MISSING action buttons; the actual UAC prompt and winget install cannot be exercised on this non-elevated host without WireGuard | `DependencyInstaller` (new), `Elevation.relaunchElevated`/`elevateCommand`, `MainApp.runAsAdministrator`/`installDependencies`/`applyDependencyFix`, `ServerDashboard` (`fixAction`), `Cli` (flag passes through), tests as above |
| No-vanish elevated relaunch (polish) | the old window no longer closes blindly when Install/Run-as-admin is clicked: it clears a marker file, relaunches elevated, waits up to 30 s for the elevated instance to write the marker (`Elevation.markStarted` in `MainApp.start` when elevated), then closes itself on success or shows a hint and **keeps the window open** on failure/UAC-cancel. A double-quoting bug that made `Start-Process -FilePath` unparseable (so no UAC ever appeared and the app vanished) was found and fixed — the executable path is now single-quoted and each argument passed separately | `Elevation` (marker handshake, `elevateCommand` psQuote fix), `MainApp` (`awaitElevatedWindow`, `markStarted`), `ElevationTest` (regression: rejects double-quoted paths) |
| Version/branding polish (polish) | `app.properties` bumped to **1.1.0** with `app.vendor` + `app.copyright` surfaced in `BuildInfo`; the Support tab shows vendor line and a live **config-encryption-at-rest** state | `app.properties`, `BuildInfo`, `SettingsView` |
| In-UI audit viewer (polish) | Settings → **Audit** tab: parses `data/audit.log` (`AuditView`), verifies the tamper-evident hash chain (status pill "hash chain verified" / "TAMPERING DETECTED"), renders the latest 300 entries newest-first with Refresh/Copy. Details are only ever stored/displayed as hashes | `AuditView` (new), `SettingsView.auditTab`, `AuditViewTest` |
| BLOCKED-status management (polish) | device list gains **Block** ⟷ **Restore** (suspends a device without losing its VPN address/key; blocked peers are already excluded from runtime config since `GatewayService` builds peers from `authorized()`) and **Remove** for BLOCKED/REVOKED; a genuine registry bug fixed — `ClientRegistry.add` now strictly rejects a VPN-address conflict against any non-revoked device (previously only logged a warning), so a blocked device truly holds its slot | `ClientRegistry` (`block`/`unblock`/`setStatus`, address-conflict rejection), `ServerDashboard` device cells, `ClientRegistryTest` (block/persist/audit + address-reserved) |
| Config encryption at rest (polish) | `config.yaml` is now **AES-256-GCM encrypted** (`ConfigCipher`, `cra-enc:v1:` header, nonce + sealed payload), key in the credential store (`config-encryption-key.secret`); legacy plaintext still loads (sidecar-verified) and upgrades to ciphertext on the next save, at which point the HMAC sidecar is superseded; wrong key or tamper → `ConfigException.STALE` with a clear message; Support tab reports the live state | `ConfigCipher` (new), `ConfigManager(Path,String,String)` (encrypt-on-save / decrypt-on-load), `AppContext` wiring, `ConfigCipherTest` + `ConfigManagerEncryptionTest` |
| Settings navigation (UX round) | the header gains a **Home** button, so Settings can always return to the dashboard (previously there was no visible way back) | `MainView` header |
| Client copy-paste-able key (UX round) | the client's WireGuard public key is now one-click **copyable** on both the client setup page and a new **MY PUBLIC KEY** card on the client dashboard (the card appears empty until `wg` is installed, then fills in) | `ClientSetupPage`, `ClientDashboard` |
| Enable-admin button + role clarity (UX round) | Settings → General adds an **Enable administrator mode…** button (self-relaunch elevated via `MainApp.runAsAdministrator`; disabled and relabeled when already elevated) plus a role banner stating this seat runs as GATEWAY or WORKSTATION and that other-role fields are disabled; the VPN tab disables **SERVER LISTEN PORT** on CLIENT seats with an explanation. Admin need (install, FULL_TUNNEL, NAT/firewall, tunnel interface) is stated in-place | `SettingsView` (General + VPN tabs) |
| Auto-detect network settings (UX round) | the gateway setup adds **Auto-detect company LAN…**, which fills the LAN subnet + interface from real detection (`NetworkManager.detectLanCidr`: `Get-NetIPAddress` PrefixLength on Windows, `ip -o -4 addr` on Linux; skips loopback/link-local/tunnel interfaces) and proposes a default VPN subnet when blank. Every field stays manually editable — auto-detect is a helper, the public endpoint remains manual because a public address cannot be detected | `ServerSetupPage`, `NetworkManager.detectLanCidr` |

**Not in this upgrade (open):** IPv6 (P1 finding #8; deliberately deferred — needs IPv6 CIDR math + routing changes + a live dual-stack host rather than half-support), polling perf (finding #9), paste-buffer injection hardening (P3), pairing-lifetime UI panel / banning / bulk-CI tooling (Phase 4 remainder; the **in-UI audit viewer** and **BLOCKED-status management** were brought in), **Phase 2 deferred items** (native Windows/macOS installers, auto-update/upgrade notifications), **Phase 3 deferred items** (OS-specific runner/sudo lifecycle, NAT/multicast troubleshooting), **Phase 4 live verification** (peer removal on revoke/rotation, gateway audit events — needs an elevated WireGuard host), and **Phase 5 deferred items** (theme syncing; uninstaller; upgrade notifications; plugin boundaries; packaging/release deliverables — version/branding polish shipped as 1.1.0), plus **live elevation/UAC + one-click install verification** (needs an elevated host with WireGuard installed). See §14/§15.