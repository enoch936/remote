# Company Remote Access

One-click secure remote access to a private/company network through a company-side
WireGuard gateway. The same desktop application runs in **SERVER (gateway)** or
**CLIENT (home)** mode.

- JavaFX 21 desktop UI with a setup wizard, dashboards, system tray and QR-code pairing.
- WireGuard for the tunnel. The application never implements cryptography itself;
  it drives the audited `wg` tooling and only stores keys in OS-protected storage.
- Zero-HTTP pairing: the admin pastes the client's public key into the gateway, the
  gateway issues a single-use, short-lived token shown as a QR code, and the client
  pastes the payload into the setup wizard.
- Split-tunnel or full-tunnel routing, with route, firewall and NAT changes tracked
  and reversed on disconnect.

## Requirements

- **JDK 21+**
- **Maven 3.9+** (build only)
- **WireGuard** installed and on `PATH` (`wg`, `wg-quick`/`wireguard.exe`). Without it
  the app runs but VPN operations report `BINARIES_MISSING` instead of failing silently.
- Firewall/NAT configuration asks for an **elevated/administrator** session on demand;
  the app surfaces a `PERMISSION_REQUIRED` notice (a reboot may be required after NAT
  setup on Windows).

## Build

```bash
mvn clean package
```

Artifacts:

- `target/company-remote-access.jar` — application jar
- `target/lib/` — runtime dependencies (JavaFX platform natives, zxing, …)

## Run

```bash
java -cp "target/company-remote-access.jar;target/lib/*" com.company.remoteaccess.Launcher
```

Or use the JavaFX Maven plugin:

```bash
mvn javafx:run
```

On first launch (no `config.yaml`) the setup wizard asks you to choose a role
(SERVER or CLIENT). A system tray icon is added and closing the window hides to tray.

## Tests

```bash
mvn test
```

Pure-JVM unit tests with deterministic doubles for the VPN adapter, ping tooling and
network detection — no privileges or WireGuard binaries are required.

## Pairing flow (CLIENT = gateway)

1. CLIENT setup page shows the machine's WireGuard **public key**. Copy it.
2. On the gateway, **Add Device** pastes that key, chooses a name, and gets the next
   free VPN address plus a one-time token (shown as a QR code / text payload).
3. On the client, click **I already have a code**, paste the payload, and the client
   stores the pinned gateway public key, endpoint and assigned address.

## Data locations (per user profile)

| What                          | Where                                  |
| ----------------------------- | -------------------------------------- |
| Configuration (non-secret)    | `~/.company-remote/config.yaml`        |
| Private keys and secrets      | OS-restricted credential store (`icacls`/`chmod 600`) |
| VPN configurations            | `~/.company-remote/vpn/`               |
| Logs                          | `~/.company-remote/logs/`              |
| Authorized device registry    | `~/.company-remote/peers.json` (server) |

Pairing tokens are stored only as SHA-256 hashes, are single-use and short-lived, and
attempts are rate-limited.

## Security model

- Private keys never appear in config files, logs or banners (central redaction).
- The state machine rejects illegal UI states; the gateway and client both record and
  surface failures instead of leaving the tunnel in an ambiguous state.
- Admin-level operations (routes, firewall, NAT) are applied only when the OS permits
  and the app tells the user exactly which requirement is missing.