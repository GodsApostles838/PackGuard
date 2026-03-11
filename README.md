# PackGuard

A reverse proxy for Minecraft Bedrock Edition that detects and blocks resource pack ripping tools. Sits between players and your server, inspects the login handshake and in-game packet stream, and prevents unauthorized pack extraction.

Built with Go and [gophertunnel](https://github.com/sandertv/gophertunnel).

## How It Works

Bedrock clients receive resource packs during the login handshake. Tools like bedrocktool exploit this by using gophertunnel to complete the handshake, download pack data (including content keys from `TexturePackInfo`), and disconnect. To the server, it looks like a normal player that left early.

PackGuard proxies every connection and applies 9 layers of detection before, during, and after the session.

## Detection Layers

### Layer 1 — Fingerprint Analysis

Scores each connecting client across 16 signals extracted from `ClientData` and `IdentityData`:

- Empty `DeviceModel` on Android (gophertunnel default)
- Classic UI profile on mobile (impossible on real devices)
- Mouse/KB input mode on Android
- Missing `PlatformOnlineID`, `DeviceID`, `SelfSignedID`
- `DeviceOS=0` or `DeviceOS=Dedicated`
- Zero-dimension skin data, empty `SkinData` payload
- `TrustedSkin=false` (not Xbox Live validated)
- Empty XUID (unauthenticated)
- Android with `MemoryTier=0`

Each signal carries a weighted score. Total above threshold = blocked before packs are sent.

### Layer 2 — Download URL Stripping

Strips `DownloadURL` from all resource packs, forcing chunked RakNet transfer through the proxy. Prevents direct CDN downloads that bypass inspection.

### Layer 3 — Rate Limiting

Per-IP connection rate limiting. Catches tools that rapid-fire reconnect after being detected.

### Layer 4 — Grab-and-Disconnect Detection

Tracks session duration. If a client receives packs but disconnects before spawning into the world (within a configurable timeout), the XUID is flagged and tracked.

### Layer 5 — XUID Reputation

Repeat offenders are auto-blocked on future connections before packs are offered. Configurable block count threshold.

### Layer 6 — Max Connections

Caps concurrent proxied connections to prevent connection flooding.

### Layer 7 + 9 — Behavioral Analysis

For players that make it to gameplay, the proxy inspects every packet in the client-to-server relay via `SessionMetrics`:

**Tick Rate Validation** — Bedrock clients send `PlayerAuthInput` at 20 Hz. Below 5 Hz or above 40 Hz = automated client.

**Tick Jitter** — Computes standard deviation of `PlayerAuthInput` intervals. Real players have natural variance (~50ms +/- noise). A stddev below 0.5ms indicates programmatic packet generation. Erratic timing patterns are also flagged.

**Velocity Validation** — Calculates horizontal speed from consecutive `PlayerAuthInput` positions. Bedrock sprint caps at ~5.6 blocks/sec, sprint-jump ~7.1. Anything above 20 blocks/sec without a server teleport acknowledgment is physically impossible.

**Capability Bitmask** — 16 behavioral flags packed into a `uint64` for O(1) pattern matching:

```
CapSentMovement | CapSentInteract | CapSentInventory | CapSprinted
CapJumped | CapSneaked | CapSwam | CapGlided | CapEmoted
CapBlockAction | CapItemInteract | CapUsedTouch | CapUsedGamepad
CapUsedMouse | CapTeleported | CapRodeVehicle
```

After 30+ seconds, if a client has been sending movement but never sprinted, jumped, sneaked, or interacted, it matches known bot signatures (`passive_observer`, `input_only_bot`).

### Layer 8 — Content Key Tracking

Generates unique AES-256 content keys per session via `TexturePackInfo.ContentKey`. Every key distribution is logged per-XUID. If a decrypted pack surfaces, you can trace it back to exactly which account extracted it.

## Getting Started

### Build

```bash
go build -o packguard .
```

### First Run

```bash
./packguard
```

On first run with no config file present, PackGuard writes a default `packguard.yaml` and exits. Edit it, then run again.

### Configuration

```yaml
listen: "0.0.0.0:19132"
auth_disabled: false

backend:
  address: "127.0.0.1:19133"

detection:
  threshold: 5.0
  block_on_detect: true
  disconnect_message: "Unable to connect to server. Please try again later."
  rate_limit: 5
  max_connections: 100
  repeat_block_count: 3
  grab_disconnect_timeout: 30
  encrypt_packs: false
  whitelist:
    - "2535416XXXXXXXXX"

log:
  file: "packguard.log"
  verbose: false
```

| Field | Description |
|---|---|
| `listen` | Address the proxy listens on. Players connect here. |
| `auth_disabled` | Disable Xbox Live authentication (for testing only). |
| `backend.address` | Your actual Bedrock server address. |
| `detection.threshold` | Score needed to block a client. Lower = stricter. Default `5.0`. |
| `detection.block_on_detect` | Whether to disconnect flagged clients or just log them. |
| `detection.disconnect_message` | Message shown to blocked players. |
| `detection.rate_limit` | Max connections per IP per minute. |
| `detection.max_connections` | Max concurrent proxied connections. |
| `detection.repeat_block_count` | Blocks before a XUID is auto-blocked permanently. |
| `detection.grab_disconnect_timeout` | Seconds — disconnect before spawn within this window = flagged. |
| `detection.encrypt_packs` | Generate per-session AES-256 content keys for pack tracking. |
| `detection.whitelist` | XUIDs that bypass fingerprint analysis. |
| `log.file` | Path for JSON Lines audit log. |
| `log.verbose` | Log clean connections too, not just blocks. |

### Headless Mode

For hosting servers, Docker, or any environment without a display:

```bash
./packguard -headless
```

Prints color-coded events to stdout:

```
  PACKGUARD v1.0.0
  0.0.0.0:19132  →  127.0.0.1:19133

[14:23:01]  BLOCKED  SkidPlayer123    192.168.1.50  (score:9.0)
[14:23:05]  ALLOWED  LegitPlayer      192.168.1.51
[14:23:08]  GRAB     SomeUser disconnected before spawn (2.3s)
[14:24:01]  STATS    blocked:1  allowed:1  total:2
```

### GUI Mode

Default mode on desktop. Opens a Fyne window with live connection log, signal breakdown per player, and stats.

```bash
./packguard
```

### Docker

```dockerfile
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /packguard .

FROM alpine:3.19
COPY --from=build /packguard /usr/local/bin/packguard
COPY packguard.yaml /etc/packguard/packguard.yaml
ENTRYPOINT ["packguard", "-headless", "-config", "/etc/packguard/packguard.yaml"]
```

### Deployment

Point `listen` to the port players connect on. Point `backend.address` to your actual Bedrock Dedicated Server. Route player traffic through the proxy:

```
Players → PackGuard (:19132) → BDS (:19133)
```

For production servers, set `auth_disabled: false` so Xbox Live authentication is enforced through the proxy.

## Flags

```
-headless       Run without GUI
-config PATH    Path to YAML config (default: packguard.yaml)
-version        Print version and exit
```

## Logging

All events are written to the log file as JSON Lines:

```json
{"time":"2025-01-15T14:23:01Z","type":"blocked","xuid":"2535416...","username":"SkidPlayer123","ip":"192.168.1.50","score":9.0,"signals":["Device Model","UI Profile","Input Mode"]}
{"time":"2025-01-15T14:23:08Z","type":"grab_disconnect","xuid":"2535416...","username":"SomeUser","duration_sec":2.3}
{"time":"2025-01-15T14:24:30Z","type":"ghost_client","xuid":"2535416...","username":"BotAccount","verdict":"ghost_client: zero PlayerAuthInput packets","hz":0,"velocity":0,"caps":"0x0"}
```

## Project Structure

```
packguard/
├── main.go              Entry point, flag parsing, GUI/headless routing
├── config/
│   └── config.go        YAML config loading and validation
├── detect/
│   ├── fingerprint.go   16-signal ClientData/IdentityData scoring engine
│   └── behavior.go      SessionMetrics, tick rate, jitter, velocity, bitmask
├── proxy/
│   ├── proxy.go         Core proxy server, connection handling, packet relay
│   ├── encryption.go    PackTracker, content key generation, distribution log
│   ├── logger.go        JSON Lines file logger
│   └── ratelimit.go     Per-IP rate limiter, XUID reputation tracker
├── ui/
│   ├── gui.go           Fyne desktop GUI
│   ├── headless.go      Terminal output for headless mode
│   └── events.go        Event type definitions
└── packguard.yaml       Configuration
```

## License

MIT
