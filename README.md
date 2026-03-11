<p align="center">
  ---<img width="838" height="223" alt="packetguard banner" src="https://github.com/user-attachments/assets/6af9b505-e0a7-44c3-8fdb-4fac5bf598d1" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.24-EF4444?style=for-the-badge&logo=go&logoColor=white" alt="Go 1.24"/>
  <img src="https://img.shields.io/badge/Bedrock-1.26.0-EF4444?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyTDIgN2wxMCA1IDEwLTV6TTIgMTdsNSAyLjV2LTVMMiAxMnptMTUgMi41TDIyIDE3di01bC01IDIuNXoiLz48L3N2Zz4=&logoColor=white" alt="Bedrock 1.26.0"/>
  <img src="https://img.shields.io/badge/Protocol-924-B91C1C?style=for-the-badge" alt="Protocol 924"/>
  <img src="https://img.shields.io/badge/License-MIT-B91C1C?style=for-the-badge" alt="MIT"/>
</p>

<p align="center">
  <b>Reverse proxy that detects and blocks resource pack ripping tools for Minecraft Bedrock servers.</b><br/>
  Sits between players and your BDS, inspects every handshake and packet stream, and shuts down extraction before packs leave the wire.
</p>

<p align="center">
  Built on <a href="https://github.com/sandertv/gophertunnel">gophertunnel</a> · GUI &amp; headless · Docker-ready
</p>




<h2>The Problem</h2>

Bedrock clients receive resource packs during the login handshake. Tools like **bedrocktool** exploit this by using gophertunnel to complete the handshake, download pack data (including content keys from `TexturePackInfo`), and disconnect. To the server, it looks like a normal player that left early.

**PackGuard proxies every connection and applies 9 layers of detection before, during, and after the session.**

---

<h2>Architecture</h2>

```
                         ┌──────────────────────┐
                         │     PACKGUARD         │
                         │     Reverse Proxy     │
  ┌──────────┐           │                       │           ┌──────────┐
  │  Player  │ ────────► │  L1  Fingerprint      │           │  Bedrock │
  │ (Client) │   :19132  │  L2  URL Strip        │           │Dedicated │
  └──────────┘           │  L3  Rate Limit       │ ────────► │  Server  │
                         │  L4  Grab Detect      │           │  :19133  │
  ┌──────────┐           │  L5  XUID Rep         │           └──────────┘
  │  Ripper  │ ────X     │  L6  Max Conns        │
  │  (Tool)  │  BLOCKED  │  L7  Behavior         │
  └──────────┘           │  L8  Encryption        │
                         │  L9  Post-Session      │
                         └──────────────────────┘
```

---

<h2>Detection Layers</h2>

| # | Stage | Detection |
|:---:|---|---|
| **1** | `Pre-Handshake` | Fingerprint analysis — 16 weighted signals from ClientData / IdentityData |
| **2** | `Handshake` | Download URL stripping — force chunked RakNet transfer through proxy |
| **3** | `Pre-Handshake` | Per-IP rate limiting — block rapid reconnect cycles |
| **4** | `Post-Session` | Grab-and-disconnect — flag clients that bail before spawning |
| **5** | `Pre-Handshake` | XUID reputation — auto-block repeat offenders |
| **6** | `Pre-Handshake` | Max concurrent connection cap |
| **7** | `In-Game` | Behavioral analysis — tick rate, jitter, velocity, capability bitmask |
| **8** | `Handshake` | Per-session AES-256 content keys with XUID distribution tracking |
| **9** | `Post-Session` | Full session verdict — aggregated behavioral score + bot pattern match |

---

<h3>Layer 1 — Fingerprint Analysis</h3>

Every connecting client is scored across **16 weighted signals** extracted from `ClientData` and `IdentityData`. Clients above the threshold are disconnected **before** resource packs are sent.

```
Signal                         Weight    Catches
─────────────────────────────────────────────────────
Empty DeviceModel (Android)    +4.0      gophertunnel default
Classic UI on mobile           +2.0      impossible on real devices
Mouse/KB input on Android      +2.0      input mode mismatch
Missing PlatformOnlineID       +1.0      absent on spoofed clients
Missing DeviceID               +1.5      absent on spoofed clients
Missing SelfSignedID           +1.0      absent on spoofed clients
DeviceOS = 0                   +3.0      unknown / unset platform
DeviceOS = Dedicated           +5.0      server posing as client
Zero-dimension skin            +2.0      no skin geometry
Empty SkinData                 +2.0      no RGBA payload
TrustedSkin = false            +1.0      not Xbox Live validated
Empty XUID                     +2.0      unauthenticated
Empty DisplayName              +1.0      empty identity
MemoryTier = 0 (Android)       +1.0      gophertunnel default
Unusual GUI Scale              +0.5      non-standard value
Empty LanguageCode             +0.5      missing locale
─────────────────────────────────────────────────────
Threshold (configurable)        5.0      default block score
```

Verdict logic:
- **Score ≥ threshold** → `BLOCKED` — disconnected immediately
- **Score ≥ threshold × 0.6** → `SUSPICIOUS` — logged, allowed through
- **Below** → `CLEAN`

---

<h3>Layer 2 — Download URL Stripping</h3>

Strips `DownloadURL` from all resource packs in the `ResourcePacksInfo` packet, forcing chunked RakNet transfer through the proxy instead of direct CDN downloads that bypass inspection entirely.

---

<h3>Layer 3 — Rate Limiting</h3>

Sliding-window per-IP rate limiter. 1-minute window, configurable connections per minute. Catches tools that rapid-fire reconnect after being detected. Cleanup runs every 60 seconds.

---

<h3>Layer 4 — Grab-and-Disconnect Detection</h3>

```
Normal Player:     Connect → Handshake → Packs → Spawn → Play → Disconnect
                                                   ▲
                                                   │ stayed past spawn

Ripping Tool:      Connect → Handshake → Packs → Disconnect
                                                   ▲
                                                   │ never spawned (flagged)
```

If a client receives packs but disconnects before spawning within a configurable timeout (default 30s), the XUID is flagged. Combined with Layer 5 for repeat tracking.

---

<h3>Layer 5 — XUID Reputation</h3>

Tracks strikes per XUID. After hitting the configurable threshold (default 3 strikes), the account is auto-blocked on future connections before packs are even offered. Bans auto-expire after 1 hour.

---

<h3>Layer 6 — Max Connections</h3>

Caps concurrent proxied connections (default 100) to prevent connection flooding and resource exhaustion.

---

<h3>Layer 7 + 9 — Behavioral Analysis</h3>

For players that make it into gameplay, the proxy inspects **every packet** in the client→server relay via `SessionMetrics`.

#### Tick Rate Validation

```
Expected:    |────|────|────|────|────|────|    20 ticks/sec (50ms apart)

Bot (fast):  |──|──|──|──|──|──|──|──|──|──|   40+ ticks/sec  → +5.0 score
Bot (slow):  |────────|────────|────────|       < 5 ticks/sec  → +5.0 score
```

Bedrock clients send `PlayerAuthInput` at 20 Hz. Anything below 5 Hz or above 40 Hz after 5 seconds = automated client.

#### Tick Jitter

```
Real Player:   48ms  52ms  49ms  53ms  47ms  51ms    stddev ~2-5ms  ✓
Bot (rigid):   50ms  50ms  50ms  50ms  50ms  50ms    stddev < 0.5ms → +4.0 score
Bot (erratic): 12ms  94ms  31ms  67ms   8ms  102ms   stddev > 25ms  → flagged
```

Standard deviation of `PlayerAuthInput` intervals over 30+ samples. Programmatic generation produces near-zero jitter. Requires mean interval > 10ms to avoid false positives.

#### Velocity Validation

```
Movement Type        Max Speed (blocks/sec)
─────────────────────────────────────────────
Walking              4.3
Sprinting            5.6
Sprint + Jump        7.1
─────────────────────────────────────────────
Impossible (no TP)   > 20.0    ← +6.0 score
```

Horizontal speed from consecutive `PlayerAuthInput` positions. Anything above 20 b/s without a server teleport acknowledgment is physically impossible.

#### Capability Bitmask

16 behavioral flags packed into a `uint64` for O(1) pattern matching:

```
Bit   Flag              Bit   Flag
───   ────              ───   ────
 0    SentMovement       8    Emoted
 1    SentInteract       9    BlockAction
 2    SentInventory     10    ItemInteract
 3    Sprinted          11    UsedTouch
 4    Jumped            12    UsedGamepad
 5    Sneaked           13    UsedMouse
 6    Swam              14    Teleported
 7    Glided            15    RodeVehicle
```

**Known bot patterns:**

| Pattern | Mask | Expected | Catches |
|---|---|---|---|
| `passive_observer` | Movement \| Interact \| Inventory | `0x000` (none set) | Zero-interaction bots |
| `input_only_bot` | Movement \| Sprint \| Jump \| Sneak | Movement only | Moves but never does anything |

After 30+ seconds, if the bitmask matches a known signature → **+3.0 score**.

#### Ghost Client Detection

If a session reaches 10+ seconds with `AuthInputCount == 0` (no `PlayerAuthInput` ever sent), it's a ghost client → **+10.0 score** (instant block).

---

<h3>Layer 8 — Content Key Tracking</h3>

```
Session A (PlayerOne):   Pack "abc-123" → ContentKey: a7f3...9e2b → logged
Session B (PlayerTwo):   Pack "abc-123" → ContentKey: d1c8...4f7a → logged
                                    ▲
                                    │ unique AES-256 key per session per XUID

Leaked pack found with key a7f3...9e2b  →  traced back to PlayerOne
```

Generates unique 32-byte AES-256 content keys per session via `crypto/rand`. Every key distribution is logged per-XUID with timestamps. Distribution log holds up to 10,000 entries. If a decrypted pack surfaces, you trace it to exactly which account extracted it.

---

<h2>Quick Start</h2>

### Build

```bash
go build -o packguard .
```

### First Run

```bash
./packguard
```

On first run with no config present, PackGuard writes a default `packguard.yaml` and exits. Edit it, then run again.

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

<details>
<summary><b>Configuration Reference</b></summary>

| Field | Type | Default | Description |
|---|:---:|:---:|---|
| `listen` | string | `0.0.0.0:19132` | Address the proxy listens on. Players connect here. |
| `auth_disabled` | bool | `false` | Disable Xbox Live auth (testing only). |
| `backend.address` | string | `127.0.0.1:19133` | Your actual BDS address. |
| `detection.threshold` | float | `5.0` | Score needed to block. Lower = stricter. |
| `detection.block_on_detect` | bool | `true` | Disconnect flagged clients or just log. |
| `detection.disconnect_message` | string | — | Message shown to blocked players. |
| `detection.rate_limit` | int | `5` | Max connections per IP per minute. |
| `detection.max_connections` | int | `100` | Max concurrent proxied connections. |
| `detection.repeat_block_count` | int | `3` | Strikes before XUID is auto-blocked. |
| `detection.grab_disconnect_timeout` | int | `30` | Seconds — disconnect before spawn = flagged. |
| `detection.encrypt_packs` | bool | `false` | Generate per-session AES-256 content keys. |
| `detection.whitelist` | []string | — | XUIDs that bypass fingerprint analysis. |
| `log.file` | string | `packguard.log` | Path for JSON Lines audit log. |
| `log.verbose` | bool | `false` | Log clean connections too. |

</details>

---

<h2>Running</h2>

### Headless

For servers, Docker, or any headless environment:

```bash
./packguard -headless
```

```
  PACKGUARD v1.0.0
  0.0.0.0:19132  →  127.0.0.1:19133

[14:23:01]  BLOCKED  SkidPlayer123    192.168.1.50  (score: 9.0)
[14:23:05]  ALLOWED  LegitPlayer      192.168.1.51
[14:23:08]  GRAB     SomeUser disconnected before spawn (2.3s)
[14:24:01]  STATS    blocked: 1  allowed: 1  total: 2
```

### GUI

Default mode on desktop. Opens a Fyne window with live connection log, signal breakdown, and stats.

```bash
./packguard
```

### Docker

```dockerfile
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /packguard .

FROM alpine:3.19
COPY --from=build /packguard /usr/local/bin/packguard
COPY packguard.yaml /etc/packguard/packguard.yaml
ENTRYPOINT ["packguard", "-headless", "-config", "/etc/packguard/packguard.yaml"]
```

### Deployment

```
Players  →  PackGuard (:19132)  →  BDS (:19133)
```

Point `listen` to the port players connect on. Point `backend.address` to your BDS. Set `auth_disabled: false` for production so Xbox Live auth is enforced through the proxy.

---

<h2>Flags</h2>

```
-headless       Run without GUI
-config PATH    Path to YAML config (default: packguard.yaml)
-version        Print version and exit
```

---

<h2>Logging</h2>

All events are written as JSON Lines to the configured log file:

```json
{"time":"2025-01-15T14:23:01Z","type":"blocked","xuid":"2535416...","username":"SkidPlayer123","ip":"192.168.1.50","score":9.0,"signals":["Device Model","UI Profile","Input Mode"]}
```

```json
{"time":"2025-01-15T14:23:08Z","type":"grab_disconnect","xuid":"2535416...","username":"SomeUser","duration_sec":2.3}
```

```json
{"time":"2025-01-15T14:24:30Z","type":"ghost_client","xuid":"2535416...","username":"BotAccount","verdict":"ghost_client","hz":0,"velocity":0,"caps":"0x0"}
```

---

<h2>Project Structure</h2>

```
packguard/
├── main.go                 Entry point, flag parsing, GUI / headless routing
├── config/
│   └── config.go           YAML loading, validation, defaults
├── detect/
│   ├── fingerprint.go      16-signal scoring engine (ClientData + IdentityData)
│   └── behavior.go         SessionMetrics — tick rate, jitter, velocity, bitmask
├── proxy/
│   ├── proxy.go            Core reverse proxy, connection handling, packet relay
│   ├── encryption.go       PackTracker, AES-256 key generation, distribution log
│   ├── logger.go           JSON Lines file logger
│   └── ratelimit.go        Per-IP rate limiter, XUID reputation tracker
├── ui/
│   ├── gui.go              Fyne desktop GUI
│   ├── headless.go         Terminal output mode
│   └── events.go           Event type definitions
├── gophertunnel-fork/      Forked gophertunnel with proxy-specific patches
└── packguard.yaml          Configuration
```

---

<p align="center">
  <img src="https://img.shields.io/badge/Made_for-Bedrock_Servers-EF4444?style=flat-square" alt="Made for Bedrock Servers"/>
  <img src="https://img.shields.io/badge/9_Detection_Layers-B91C1C?style=flat-square" alt="9 Detection Layers"/>
  <img src="https://img.shields.io/badge/AES--256_Encryption-991B1B?style=flat-square" alt="AES-256"/>
</p>

<p align="center"><b>MIT License</b></p>
