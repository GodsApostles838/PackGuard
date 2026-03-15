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
  Reverse proxy for Bedrock servers — sits in front of BDS, catches ripping tools, lets real players through.
</p>

<p align="center">
  Built on <a href="https://github.com/sandertv/gophertunnel">gophertunnel</a> · GUI &amp; headless · Docker-ready ·
  <a href="https://github.com/GodsApostles838/PackGuard/wiki"><img src="https://img.shields.io/badge/Wiki-Click_Me-EF4444?style=for-the-badge" alt="Wiki"/></a>
</p>

---

## Why this exists

Bedrock clients get resource packs during the login handshake. That's just how the protocol works. Tools like **bedrocktool** abuse this — they connect with gophertunnel, grab the packs (content keys included from `TexturePackInfo`), and bail. From your server's perspective it just looks like someone joined and left.

PackGuard sits between players and your BDS. Every connection goes through 9 detection layers before, during, and after the session. Rippers get blocked. Normal players don't notice it's there.

---

## How it works

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

Quick summary of each layer:

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
| **9** | `Post-Session` | Final verdict from everything above — aggregated score + known bot patterns |

---

## Fingerprinting (Layer 1)

This is the first line of defence and catches most tools outright. Every connection gets scored across 16 weighted signals before any packs are sent:

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

Score hits threshold? Blocked before packs are even offered. Score hits 60% of threshold? Logged as suspicious but let through. Below that, clean.

---

## Behavioral analysis (Layers 7 + 9)

For anything that makes it past fingerprinting, the proxy watches the actual gameplay session.

**Tick rate** — Bedrock clients send `PlayerAuthInput` at 20 Hz. Below 5 Hz or above 40 Hz after 5 seconds of play = not a real client.

**Jitter** — real humans have ~2-5ms standard deviation between ticks. Bots either have near-zero jitter (programmatic timing) or wildly erratic intervals. Both stand out.

**Movement speed** — walking caps at 4.3 b/s, sprinting at 5.6, sprint+jump at 7.1. Anything over 20 b/s without a server teleport is physically impossible.

**Capability bitmask** — 16 flags (movement, interaction, inventory, sprint, jump, emote, etc) packed into a uint64. Known bot patterns like zero-interaction or movement-only get matched after 30+ seconds. If someone's been connected for half a minute and hasn't done *anything* a normal player would do, that's a red flag.

**Ghost clients** — 10+ seconds with zero `PlayerAuthInput` packets = instant block. Not even pretending to be a player at that point.

---

## Grab-and-disconnect (Layer 4)

```
Real player:    Connect → Handshake → Packs → Spawn → Play → Disconnect
Ripper:         Connect → Handshake → Packs → Disconnect  (never spawned)
```

If you disconnect within 30 seconds (configurable) without ever spawning, that gets flagged. Combined with the XUID reputation system — 3 strikes and you're auto-blocked on sight.

---

## Content key tracking (Layer 8)

Every session gets a unique 32-byte AES-256 key via `crypto/rand`. The key + XUID + timestamp gets logged. If someone leaks a decrypted pack, you look up which key decrypted it and trace it back to the exact account. Log holds up to 10k entries.

---

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

---

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

---

## CLI flags

```
-headless       No GUI
-config PATH    Config file (default: packguard.yaml)
-version        Print version
```

---

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

---

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

---

<p align="center">
  <img src="https://img.shields.io/badge/Made_for-Bedrock_Servers-EF4444?style=flat-square" alt="Made for Bedrock Servers"/>
  <img src="https://img.shields.io/badge/9_Detection_Layers-B91C1C?style=flat-square" alt="9 Detection Layers"/>
  <img src="https://img.shields.io/badge/AES--256_Encryption-991B1B?style=flat-square" alt="AES-256"/>
</p>

<p align="center"><b>MIT License</b></p>
