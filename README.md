<p align="center">
  <img width="838" height="223" alt="packetguard banner" src="https://github.com/user-attachments/assets/7d55d330-183d-463b-8a4b-68c79477291f" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.24-EF4444?style=for-the-badge&logo=go&logoColor=white" alt="Go 1.24"/>
  <img src="https://img.shields.io/badge/Bedrock-1.26.0-EF4444?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyTDIgN2wxMCA1IDEwLTV6TTIgMTdsNSAyLjV2LTVMMiAxMnptMTUgMi41TDIyIDE3di01bC01IDIuNXoiLz48L3N2Zz4=&logoColor=white" alt="Bedrock 1.26.0"/>
  <img src="https://img.shields.io/badge/Protocol-924-B91C1C?style=for-the-badge" alt="Protocol 924"/>
  <img src="https://img.shields.io/badge/License-MIT-B91C1C?style=for-the-badge" alt="MIT"/>
</p>

<p align="center">
  <b>Stop people stealing your resource packs.</b><br/>
  Reverse proxy for Bedrock servers, sits in front of BDS, catches ripping tools, lets real players through.
</p>

<p align="center">
  Built on <a href="https://github.com/sandertv/gophertunnel">gophertunnel</a> · GUI &amp; headless · Docker-ready ·
  <a href="https://github.com/GodsApostles838/PackGuard/wiki"><img src="https://img.shields.io/badge/Wiki-Click_Me-EF4444?style=for-the-badge" alt="Wiki"/></a>
</p>


## Why this exists

Bedrock's resource pack system is fundamentally broken from a security standpoint. During the login handshake the server sends a `ResourcePacksInfo` packet that contains the pack UUIDs, sizes, and — critically — content keys in plaintext via `TexturePackInfo`. The client needs these to decrypt the packs after download. There's no way around it, that's just how Mojang built the protocol.

Tools like **bedrocktool** exploit this. They use gophertunnel to complete a legitimate handshake, receive the `ResourcePacksInfo` + `ResourcePackDataInfo` packets, download every chunk, and disconnect. The whole process takes about 2-3 seconds. Your server sees a normal join followed by an early leave. You'd never know anything happened unless you were specifically watching session durations.

The core issue is that BDS has zero awareness of *why* a client is connecting. It can't distinguish between a kid on an iPad and a Go binary running `minecraft.Dial()`. PackGuard can, because it's intercepting and inspecting every packet in the relay rather than just forwarding blindly.


## How it works

PackGuard binds to a port (default `:19132`), accepts RakNet connections, and opens a mirrored connection to your actual BDS (default `:19133`). Every packet flows through the proxy in both directions. The proxy doesn't modify game traffic for legitimate players — it just watches.

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

Detection happens at three stages of a connection's lifecycle:

**Before packs are sent** (L1, L3, L5, L6) — fingerprint scoring, rate limiting, reputation check, connection cap. If any of these trip, the client gets disconnected before `ResourcePacksInfo` is ever forwarded. No packs exposed.

**During the handshake** (L2, L8) — download URLs get stripped from pack entries so the client can't just `GET` the CDN link directly. If encryption is enabled, each session gets unique AES-256 content keys so you can trace leaks to a specific XUID.

**During and after gameplay** (L4, L7, L9) — behavioral monitoring runs for the entire session. Tick rate, movement physics, interaction patterns, session duration. The post-session verdict combines all the behavioral scores into a final call.

| # | When | What it does |
|:---:|---|---|
| **1** | `Pre-Handshake` | Scores 16 signals from ClientData/IdentityData — catches gophertunnel defaults, spoofed devices, missing auth |
| **2** | `Handshake` | Strips download URLs so packs have to transfer through the proxy, not direct from CDN |
| **3** | `Pre-Handshake` | Rate limits per IP — stops rapid reconnect spam |
| **4** | `Post-Session` | Flags clients that grab packs then disconnect before spawning |
| **5** | `Pre-Handshake` | Tracks strikes per XUID — repeat offenders get auto-blocked |
| **6** | `Pre-Handshake` | Caps concurrent connections so you don't get flooded |
| **7** | `In-Game` | Watches tick rate, movement speed, jitter, interaction patterns |
| **8** | `Handshake` | Unique AES-256 key per session — if a pack leaks you know exactly who |
| **9** | `Post-Session` | Final verdict from everything above — aggregated behavioral score + bot pattern match |


## Fingerprinting (Layer 1)

This is where most rippers die. When a Bedrock client connects, it sends `ClientData` and `IdentityData` as part of the login JWT chain. Real clients (Windows 10, iOS, Android, Xbox, Switch, PS) populate these fields from actual hardware and OS APIs. Gophertunnel and similar libraries don't — they either leave fields empty or fill them with values that don't make physical sense.

The fingerprint engine in `detect/fingerprint.go` pulls 16 fields and scores them:

```
Signal                         Weight    Why
─────────────────────────────────────────────────────
Empty DeviceModel (Android)    +4.0      gophertunnel doesn't set this
Classic UI on mobile           +2.0      literally impossible on real phones
Mouse/KB input on Android      +2.0      input mode doesn't match platform
Missing PlatformOnlineID       +1.0      spoofed clients skip this
Missing DeviceID               +1.5      same deal
Missing SelfSignedID           +1.0      same deal
DeviceOS = 0                   +3.0      unknown platform
DeviceOS = Dedicated           +5.0      server pretending to be a client lol
Zero-dimension skin            +2.0      no skin geometry at all
Empty SkinData                 +2.0      no RGBA pixel data
TrustedSkin = false            +1.0      not validated by Xbox Live
Empty XUID                     +2.0      not authenticated
Empty DisplayName              +1.0      no gamertag
MemoryTier = 0 (Android)       +1.0      another gophertunnel default
Unusual GUI Scale              +0.5      non-standard value
Empty LanguageCode             +0.5      missing locale
─────────────────────────────────────────────────────
Default threshold               5.0      configurable
```

The weights aren't random. `DeviceOS = Dedicated` is +5.0 because there is literally no scenario where a dedicated server binary connects as a client — that's a guaranteed bot. `Empty DeviceModel` on Android is +4.0 because every real Android device reports a model string from `Build.MODEL`, but gophertunnel's `login.ClientData` struct initialises it as `""`. A real phone would never do that.

The scoring uses three tiers:
- **Score >= threshold** — `BLOCKED`, disconnected before packs are sent
- **Score >= threshold * 0.6** — `SUSPICIOUS`, logged but allowed through (useful for tuning)
- **Below** — `CLEAN`

The 0.6x band exists so you can review near-misses in your logs and adjust the threshold. If you're seeing a lot of `SUSPICIOUS` entries from legit players on weird devices, bump the threshold up. If rippers are sliding through at 4.9, drop it.


## Behavioral analysis (Layers 7 + 9)

Fingerprinting catches the lazy tools. But if someone forks gophertunnel and starts spoofing ClientData properly, you need a second line. That's what `detect/behavior.go` does — it watches the actual packet stream after the player joins.

Every proxied session has a `SessionMetrics` struct that accumulates data from `PlayerAuthInput` packets in real time:

**Tick rate** — Bedrock clients send `PlayerAuthInput` at 20 Hz (once every 50ms). This is hardcoded in the client, you can't change it. The proxy counts packets over a rolling window. Below 5 Hz or above 40 Hz after the first 5 seconds = automated. We wait 5 seconds because real clients can stutter briefly on join while chunks load.

**Tick jitter** — this is the one that's hard to fake. Real human input has natural variance in packet timing — network jitter, OS scheduling, the client's own frame timing. Standard deviation across 30+ samples lands around 2-5ms for a real player. Bots using `time.Sleep(50 * time.Millisecond)` produce near-zero stddev because Go's scheduler is too consistent. Bots using random delays tend to overshoot and get stddev > 25ms. Both patterns are detectable. We require mean interval > 10ms before scoring to avoid false positives on clients that batch-send on reconnect.

**Movement speed** — consecutive `PlayerAuthInput` packets contain position vectors. We compute horizontal displacement per tick. Walking caps at 4.3 blocks/sec, sprinting at 5.6, sprint+jump at 7.1. These are Bedrock's actual physics constants. Anything over 20 b/s without a preceding server teleport packet (`MovePlayer` with mode `Teleport`) is physically impossible — no elytra, no riptide, nothing gets you there legitimately.

**Capability bitmask** — 16 behavioral flags packed into a `uint64`. Every time a player sprints, jumps, interacts, opens inventory, uses touch input, etc., the corresponding bit gets set. After 30+ seconds, if the bitmask matches a known bot signature (like zero interaction, or movement-only with no jumps/sneaks), that's +3.0 to the score. Real players *do things*. Bots that just idle or walk in straight lines don't.

**Ghost clients** — if 10+ seconds pass and `AuthInputCount` is still 0 (the client hasn't sent a single `PlayerAuthInput`), that's a +10.0 instant block. At that point the "player" is just holding the connection open without participating in the game at all. No legitimate client does this.

The Layer 9 post-session verdict fires on disconnect. It takes the accumulated behavioral scores, checks for grab-and-disconnect (Layer 4), and produces the final log entry.


## Grab-and-disconnect (Layer 4)

This is the simplest and most reliable signal. Normal players connect, get packs, spawn into the world, walk around, disconnect eventually. Ripping tools connect, get packs, and disconnect immediately — usually within 2-3 seconds, always before the spawn sequence completes.

```
Real player:    Connect → Handshake → Packs → Spawn → Play → Disconnect
Ripper:         Connect → Handshake → Packs → Disconnect  (never spawned)
```

If a client receives resource pack data but disconnects within 30 seconds (configurable) without the proxy ever seeing a spawn confirmation, the XUID gets a strike. This feeds into Layer 5 — after 3 strikes (configurable), the XUID is auto-blocked on future connections before packs are even offered. Bans auto-expire after 1 hour so legitimate players who happened to crash during loading aren't permanently locked out.

The timeout exists because real players *can* disconnect during loading — maybe they fat-fingered the back button, maybe their wifi dropped. One disconnect isn't suspicious. Three in a row from the same Xbox account is.


## URL stripping (Layer 2)

When BDS sends `ResourcePacksInfo`, each pack entry can include a `DownloadURL` field. If set, the client downloads the pack directly from that URL (usually a CDN) instead of requesting chunks through the RakNet connection. This is faster for large packs but completely bypasses the proxy — the client just does a plain HTTP GET and PackGuard never sees the traffic.

Layer 2 strips this field from every pack entry before forwarding the packet. The client falls back to chunked RakNet transfer, which flows through the proxy where it can be monitored and rate-limited. This is also what makes Layer 8 encryption possible — you can't encrypt a CDN download with per-session keys.


## Content key tracking (Layer 8)

This one's optional (`encrypt_packs: false` by default) because it adds overhead, but it's the nuclear option for tracking leaks. When enabled, PackGuard generates a unique 32-byte AES-256 key per session per pack via `crypto/rand`. The key gets injected into the pack's content key field in `TexturePackInfo` and logged alongside the XUID and timestamp in `proxy/encryption.go`.

The distribution log holds up to 10,000 entries in a ring buffer. If a decrypted resource pack shows up on some Discord server, you extract the content key from the pack header, grep your log, and you know exactly which Xbox account downloaded it and when. It's forensic evidence, not prevention — but sometimes knowing *who* is enough.


## Quick start

```bash
go build -o packguard .
./packguard
```

First run with no config writes a default `packguard.yaml` and exits. Edit it, run again.

### Config

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
<summary><b>Full config reference</b></summary>

| Field | Type | Default | What it does |
|---|:---:|:---:|---|
| `listen` | string | `0.0.0.0:19132` | Port players connect to |
| `auth_disabled` | bool | `false` | Skip Xbox Live auth (don't do this in prod) |
| `backend.address` | string | `127.0.0.1:19133` | Your actual BDS |
| `detection.threshold` | float | `5.0` | Fingerprint score to block at. Lower = stricter |
| `detection.block_on_detect` | bool | `true` | Actually disconnect or just log |
| `detection.disconnect_message` | string | — | What blocked players see |
| `detection.rate_limit` | int | `5` | Connections per IP per minute |
| `detection.max_connections` | int | `100` | Total concurrent connections |
| `detection.repeat_block_count` | int | `3` | Strikes before auto-block |
| `detection.grab_disconnect_timeout` | int | `30` | Seconds before no-spawn = flagged |
| `detection.encrypt_packs` | bool | `false` | Per-session AES-256 keys |
| `detection.whitelist` | []string | — | XUIDs that skip fingerprinting |
| `log.file` | string | `packguard.log` | Log file path |
| `log.verbose` | bool | `false` | Log clean connections too |

</details>


## Running

**Headless** (servers, Docker, CI):
```bash
./packguard -headless
```

**GUI** (desktop, default):
```bash
./packguard
```

Fyne window with live connection log, signal breakdowns, stats.

**Docker**:
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

**Deployment is just**:
```
Players  →  PackGuard (:19132)  →  BDS (:19133)
```

Point players at PackGuard's port. Point PackGuard at your BDS. Done.


## CLI flags

```
-headless       No GUI
-config PATH    Config file (default: packguard.yaml)
-version        Print version
```


## Logs

JSON Lines to the configured log file:

```json
{"time":"2025-01-15T14:23:01Z","type":"blocked","xuid":"2535416...","username":"SkidPlayer123","ip":"192.168.1.50","score":9.0,"signals":["Device Model","UI Profile","Input Mode"]}
```
```json
{"time":"2025-01-15T14:23:08Z","type":"grab_disconnect","xuid":"2535416...","username":"SomeUser","duration_sec":2.3}
```
```json
{"time":"2025-01-15T14:24:30Z","type":"ghost_client","xuid":"2535416...","username":"BotAccount","verdict":"ghost_client","hz":0,"velocity":0,"caps":"0x0"}
```


## Project layout

```
packguard/
├── main.go                 entrypoint, flags, GUI/headless routing
├── config/
│   └── config.go           YAML loading + defaults
├── detect/
│   ├── fingerprint.go      16-signal scoring engine
│   └── behavior.go         tick rate, jitter, velocity, bitmask
├── proxy/
│   ├── proxy.go            reverse proxy + packet relay
│   ├── encryption.go       AES-256 key gen + distribution log
│   ├── logger.go           JSON Lines logger
│   └── ratelimit.go        rate limiter + XUID reputation
├── ui/
│   ├── gui.go              Fyne GUI
│   ├── headless.go         terminal mode
│   └── events.go           event types
├── gophertunnel-fork/      patched gophertunnel
└── packguard.yaml          config
```


## Why gophertunnel fork?

PackGuard uses a forked version of gophertunnel because we need access to raw packet data at points in the handshake where upstream doesn't expose it. Specifically, we need to intercept `ResourcePacksInfo` before it's forwarded to strip download URLs, and we need to inject modified content keys into the pack entries. Upstream gophertunnel handles this internally and doesn't give you hooks. The fork adds callback points in the handshake sequence without changing the rest of the library.


<p align="center">
  <img src="https://img.shields.io/badge/Made_for-Bedrock_Servers-EF4444?style=flat-square" alt="Made for Bedrock Servers"/>
  <img src="https://img.shields.io/badge/9_Detection_Layers-B91C1C?style=flat-square" alt="9 Detection Layers"/>
  <img src="https://img.shields.io/badge/AES--256_Encryption-991B1B?style=flat-square" alt="AES-256"/>
</p>

<p align="center"><b>MIT License</b></p>
