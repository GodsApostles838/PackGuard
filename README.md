<p align="center">
  <img src="https://img.shields.io/badge/Minecraft_Bedrock-1.26.0-green?style=for-the-badge" alt="Bedrock 1.26.0"/>
  <img src="https://img.shields.io/badge/Protocol-924-blue?style=for-the-badge" alt="Protocol 924"/>
  <img src="https://img.shields.io/badge/Go-1.23-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go 1.23"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="MIT License"/>
</p>

<h1 align="center">PackGuard</h1>

<p align="center"><img width="363" height="380" alt="untitled" src="https://github.com/user-attachments/assets/6eed0d38-e628-4f5b-a375-b873f5902236" />

  A reverse proxy for Minecraft Bedrock Edition that detects and blocks resource pack ripping tools.<br/>
  Sits between players and your server, inspects the login handshake and in-game packet stream,<br/>
  and prevents unauthorized pack extraction.
</p>

<p align="center">
  Built with Go and <a href="https://github.com/sandertv/gophertunnel">gophertunnel</a>.
</p>

---

## The Problem

Bedrock clients receive resource packs during the login handshake. Tools like bedrocktool exploit this by using gophertunnel to complete the handshake, download pack data (including content keys from `TexturePackInfo`), and disconnect. To the server, it looks like a normal player that left early.

PackGuard proxies every connection and applies **9 layers of detection** before, during, and after the session.

## Architecture

```
                         +----------------------+
                         |   PackGuard          |
                         |   Reverse Proxy      |
  +----------+           |                      |        +----------+
  |  Player  | --------> | Layer 1: Fingerprint |        |  Bedrock |
  | (Client) |  :19132   | Layer 2: URL Strip   |        | Dedicated|
  +----------+           | Layer 3: Rate Limit  |        |  Server  |
                         | Layer 4: Grab Detect -------> |  :19133  |
  +----------+           | Layer 5: XUID Rep    |        +----------+
  |  Ripper  | ----X     | Layer 6: Max Conns   |
  |  (Tool)  |  BLOCKED  | Layer 7: Behavior    |
  +----------+           | Layer 8: Encryption  |
                         | Layer 9: Post-Session|
                         +----------------------+
```

## Detection Layers

<table>
  <tr>
    <th>Layer</th>
    <th>Stage</th>
    <th>What It Does</th>
  </tr>
  <tr>
    <td><b>1</b></td>
    <td><code>Pre-Handshake</code></td>
    <td>Fingerprint analysis - 16 weighted signals from ClientData/IdentityData</td>
  </tr>
  <tr>
    <td><b>2</b></td>
    <td><code>Handshake</code></td>
    <td>Strip DownloadURL - force chunked RakNet transfer through proxy</td>
  </tr>
  <tr>
    <td><b>3</b></td>
    <td><code>Pre-Handshake</code></td>
    <td>Per-IP rate limiting - block rapid reconnect cycles</td>
  </tr>
  <tr>
    <td><b>4</b></td>
    <td><code>Post-Session</code></td>
    <td>Grab-and-disconnect - flag clients that bail before spawning</td>
  </tr>
  <tr>
    <td><b>5</b></td>
    <td><code>Pre-Handshake</code></td>
    <td>XUID reputation - auto-block repeat offenders</td>
  </tr>
  <tr>
    <td><b>6</b></td>
    <td><code>Pre-Handshake</code></td>
    <td>Max concurrent connections cap</td>
  </tr>
  <tr>
    <td><b>7 + 9</b></td>
    <td><code>In-Game</code></td>
    <td>Behavioral analysis - tick rate, jitter, velocity, capability bitmask</td>
  </tr>
  <tr>
    <td><b>8</b></td>
    <td><code>Handshake</code></td>
    <td>Per-session AES-256 content keys with XUID distribution tracking</td>
  </tr>
</table>

---

### Layer 1 - Fingerprint Analysis

Scores each connecting client across 16 signals extracted from `ClientData` and `IdentityData`:

```
Signal                         Weight    Catches
-----------------------------------------------------
Empty DeviceModel (Android)    +2.0      gophertunnel default
Classic UI on mobile           +1.5      impossible on real devices
Mouse/KB input on Android      +1.5      input mode mismatch
Missing PlatformOnlineID       +1.0      absent on spoofed clients
Missing DeviceID               +1.0      absent on spoofed clients
Missing SelfSignedID           +1.0      absent on spoofed clients
DeviceOS = 0                   +2.0      unknown/unset platform
DeviceOS = Dedicated           +3.0      server posing as client
Zero-dimension skin            +1.5      no skin geometry
Empty SkinData                 +1.5      no skin payload
TrustedSkin = false            +1.0      not Xbox Live validated
Empty XUID                     +2.0      unauthenticated
MemoryTier = 0 (Android)       +1.0      default/unset memory
SkinImageWidth = 0             +1.0      invalid skin dimensions
Empty AnimatedImageData        +0.5      missing animation frames
Mismatched ThirdPartyName      +0.5      name inconsistency
-----------------------------------------------------
Threshold (configurable)        5.0      default block score
```

> Clients that score above the threshold are disconnected **before** resource packs are sent.

---

### Layer 2 - Download URL Stripping

Strips `DownloadURL` from all resource packs in the `ResourcePacksInfo` packet, forcing chunked RakNet transfer through the proxy instead of direct CDN downloads that bypass inspection entirely.

---

### Layer 3 - Rate Limiting

Per-IP connection rate limiting. Catches tools that rapid-fire reconnect after being detected.

---

### Layer 4 - Grab-and-Disconnect Detection

```
Normal Player:     Connect -> Handshake -> Packs -> Spawn -> Play -> Disconnect
                                                     ^
                                                     | stayed past spawn

Ripping Tool:      Connect -> Handshake -> Packs -> Disconnect
                                                     ^
                                                     | never spawned (flagged)
```

If a client receives packs but disconnects before spawning (within a configurable timeout), the XUID is flagged and tracked.

---

### Layer 5 - XUID Reputation

Repeat offenders are auto-blocked on future connections before packs are offered. Configurable block count threshold.

---

### Layer 6 - Max Connections

Caps concurrent proxied connections to prevent connection flooding.

---

### Layer 7 + 9 - Behavioral Analysis

For players that make it to gameplay, the proxy inspects every packet in the client-to-server relay via `SessionMetrics`:

#### Tick Rate Validation

```
Expected:    |----|----|----|----|----|----|    20 ticks/sec (50ms apart)

Bot (fast):  |--|--|--|--|--|--|--|--|--|--|    40+ ticks/sec
Bot (slow):  |--------|--------|--------|      < 5 ticks/sec
```

Bedrock clients send `PlayerAuthInput` at 20 Hz. Below 5 Hz or above 40 Hz = automated client.

#### Tick Jitter

```
Real Player:   48ms  52ms  49ms  53ms  47ms  51ms    stddev ~2-5ms
Bot (rigid):   50ms  50ms  50ms  50ms  50ms  50ms    stddev < 0.5ms
Bot (erratic): 12ms  94ms  31ms  67ms   8ms  102ms   stddev > 25ms
```

Standard deviation of `PlayerAuthInput` intervals. Real players have natural variance. Programmatic generation produces near-zero or wildly erratic timing.

#### Velocity Validation

```
Movement Type        Max Speed (blocks/sec)
-----------------------------------------------
Walking              4.3
Sprinting            5.6
Sprint + Jump        7.1
-----------------------------------------------
Impossible (no TP)   > 20.0    <- flagged
```

Calculates horizontal speed from consecutive `PlayerAuthInput` positions. Anything above 20 blocks/sec without a server teleport acknowledgment is physically impossible.

#### Capability Bitmask

16 behavioral flags packed into a `uint64` for O(1) pattern matching:

```
Bit   Flag              Bit   Flag
---   ----              ---   ----
 0    SentMovement       8    Emoted
 1    SentInteract       9    BlockAction
 2    SentInventory     10    ItemInteract
 3    Sprinted          11    UsedTouch
 4    Jumped            12    UsedGamepad
 5    Sneaked           13    UsedMouse
 6    Swam              14    Teleported
 7    Glided            15    RodeVehicle
```

**Known bot pattern matching:**

```
Pattern             Mask                                Expected
-----------------------------------------------------------------
passive_observer    Movement | Interact | Inventory     0x000 (none set)
input_only_bot      Movement | Sprint | Jump | Sneak    Movement only
```

After 30+ seconds, if a client has been sending movement but never sprinted, jumped, sneaked, or interacted, it matches known bot signatures.

---

### Layer 8 - Content Key Tracking

```
Session A (PlayerOne):   Pack "abc-123" -> ContentKey: a7f3...9e2b -> logged
Session B (PlayerTwo):   Pack "abc-123" -> ContentKey: d1c8...4f7a -> logged
                                    ^
                                    | unique key per session per XUID

Leaked pack found with key a7f3...9e2b  ->  traced to PlayerOne
```

Generates unique AES-256 content keys per session via `TexturePackInfo.ContentKey`. Every key distribution is logged per-XUID. If a decrypted pack surfaces, you can trace it back to exactly which account extracted it.

---

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

<details>
<summary><b>Configuration Reference</b></summary>

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
| `detection.grab_disconnect_timeout` | Seconds -- disconnect before spawn within this window = flagged. |
| `detection.encrypt_packs` | Generate per-session AES-256 content keys for pack tracking. |
| `detection.whitelist` | XUIDs that bypass fingerprint analysis. |
| `log.file` | Path for JSON Lines audit log. |
| `log.verbose` | Log clean connections too, not just blocks. |

</details>

---

## Running

### Headless Mode

For hosting servers, Docker, or any environment without a display:

```bash
./packguard -headless
```

```
  PACKGUARD v1.0.0
  0.0.0.0:19132  ->  127.0.0.1:19133

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

```
Players  ->  PackGuard (:19132)  ->  BDS (:19133)
```

Point `listen` to the port players connect on. Point `backend.address` to your actual Bedrock Dedicated Server. For production, set `auth_disabled: false` so Xbox Live authentication is enforced through the proxy.

---

## Flags

```
-headless       Run without GUI
-config PATH    Path to YAML config (default: packguard.yaml)
-version        Print version and exit
```

---

## Logging

All events are written as JSON Lines:

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

## Project Structure

```
packguard/
|-- main.go                 Entry point, flag parsing, GUI/headless routing
|-- config/
|   +-- config.go           YAML config loading and validation
|-- detect/
|   |-- fingerprint.go      16-signal ClientData/IdentityData scoring engine
|   +-- behavior.go         SessionMetrics, tick rate, jitter, velocity, bitmask
|-- proxy/
|   |-- proxy.go            Core proxy server, connection handling, packet relay
|   |-- encryption.go       PackTracker, content key generation, distribution log
|   |-- logger.go           JSON Lines file logger
|   +-- ratelimit.go        Per-IP rate limiter, XUID reputation tracker
|-- ui/
|   |-- gui.go              Fyne desktop GUI
|   |-- headless.go         Terminal output for headless mode
|   +-- events.go           Event type definitions
+-- packguard.yaml          Configuration
```

---

## License

MIT
