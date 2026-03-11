// Copyright (c) Savor. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root.

package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"packguard/config"
	"packguard/detect"
	"packguard/ui"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

type ConnID = string

type Server struct {
	cfg    *config.Config
	events chan<- ui.Event
	logger *FileLogger

	verdicts    sync.Map
	rateLimiter *RateLimiter
	xuidTracker *XUIDTracker
	packTracker *PackTracker
	activeConns atomic.Int64
}

func NewServer(cfg *config.Config, events chan<- ui.Event, logger *FileLogger) *Server {
	return &Server{
		cfg:         cfg,
		events:      events,
		logger:      logger,
		rateLimiter: NewRateLimiter(cfg.Detection.RateLimit),
		xuidTracker: NewXUIDTracker(cfg.Detection.RepeatBlockCount),
		packTracker: NewPackTracker(cfg.Detection.EncryptPacks),
	}
}

func (s *Server) Run(ctx context.Context) error {
	// Probe backend for ResourcePacks via initial RakNet handshake.
	var packs []*resource.Pack
	probe, err := minecraft.Dialer{}.DialContext(ctx, "raknet", s.cfg.Backend.Address)
	if err == nil {
		packs = probe.ResourcePacks()
		probe.Close()
		s.emit(ui.Event{
			Type:    ui.EventProxyStarted,
			Time:    time.Now(),
			Message: fmt.Sprintf("Discovered %d resource pack(s) from backend", len(packs)),
		})
	} else {
		s.emit(ui.Event{
			Type:    ui.EventError,
			Time:    time.Now(),
			Message: fmt.Sprintf("Backend probe failed: %s", err),
		})
	}

	// Strip DownloadURLs — force chunked RakNet transfer through proxy.
	packs = stripDownloadURLs(packs)

	// Layer 8: compute pack SHA256 signatures and apply content keys.
	sigs := s.packTracker.ComputeSignatures(packs)
	for _, sig := range sigs {
		s.emit(ui.Event{
			Type:    ui.EventProxyStarted,
			Time:    time.Now(),
			Message: fmt.Sprintf("Pack %s v%s — SHA256:%s (%d bytes, encrypted:%v)", sig.Name, sig.Version, sig.SHA256[:16], sig.Size, sig.HasKey),
		})
	}
	packs = s.packTracker.ApplyContentKeys(packs)

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.rateLimiter.Cleanup()
			}
		}
	}()

	listener, err := minecraft.ListenConfig{
		StatusProvider:         minecraft.NewStatusProvider("PackGuard", ""),
		AuthenticationDisabled: s.cfg.AuthDisabled,
		ResourcePacks:          packs,
		FetchResourcePacks: func(
			identity login.IdentityData,
			client login.ClientData,
			current []*resource.Pack,
		) []*resource.Pack {
			// Layer 5: XUID reputation — auto-block repeat offenders.
			if s.xuidTracker.IsBlocked(identity.XUID) {
				fp := &detect.Fingerprint{
					XUID:        identity.XUID,
					Username:    identity.DisplayName,
					UUID:        identity.Identity,
					Verdict:     detect.VerdictBlocked,
					ConnectedAt: time.Now(),
				}
				s.verdicts.Store(identity.Identity, fp)
				s.emitBlocked(fp, "repeat offender — auto-blocked")
				return []*resource.Pack{}
			}

			// Layer 1: ClientData/IdentityData fingerprint analysis.
			fp := detect.Analyze(identity, client, detect.Score(s.cfg.Detection.Threshold))

			if s.cfg.IsWhitelisted(identity.XUID) {
				fp.Verdict = detect.VerdictClean
				fp.TotalScore = 0
				fp.Signals = nil
			}

			s.verdicts.Store(identity.Identity, fp)

			if fp.Verdict == detect.VerdictBlocked && s.cfg.Detection.BlockOnDetect {
				s.xuidTracker.RecordBlock(identity.XUID)
				s.emitBlocked(fp, "")
				return []*resource.Pack{}
			}

			// Layer 8: record TexturePackInfo content key distribution.
			s.packTracker.RecordDistribution(identity.XUID, identity.DisplayName, current)
			if s.logger != nil {
				for _, p := range current {
					if key := p.ContentKey(); key != "" {
						s.logger.LogPackServed(identity.XUID, identity.DisplayName, p.UUID().String(), key)
					}
				}
			}

			return current
		},
	}.Listen("raknet", s.cfg.Listen)
	if err != nil {
		s.emit(ui.Event{
			Type:    ui.EventError,
			Time:    time.Now(),
			Message: fmt.Sprintf("Failed to listen on %s: %s", s.cfg.Listen, err),
		})
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()

	s.emit(ui.Event{
		Type:    ui.EventProxyStarted,
		Time:    time.Now(),
		Message: fmt.Sprintf("PackGuard v%s — listening on %s → %s", config.Version, s.cfg.Listen, s.cfg.Backend.Address),
	})

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				s.emit(ui.Event{
					Type:    ui.EventError,
					Time:    time.Now(),
					Message: fmt.Sprintf("accept error: %s", err),
				})
				continue
			}
		}
		go s.handleConn(ctx, conn.(*minecraft.Conn))
	}
}

func (s *Server) handleConn(ctx context.Context, conn *minecraft.Conn) {
	identity := conn.IdentityData()
	connID := ConnID(fmt.Sprintf("%s-%d", identity.XUID, time.Now().UnixNano()))
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// Layer 3: per-IP RakNet connection rate limiting.
	if !s.rateLimiter.Allow(ip) {
		s.emit(ui.Event{
			Type:    ui.EventRateLimited,
			Time:    time.Now(),
			Message: fmt.Sprintf("Rate limited %s (%s)", identity.DisplayName, ip),
			ConnID:  connID,
		})
		if s.logger != nil {
			s.logger.LogRateLimited(ip)
		}
		conn.WritePacket(&packet.Disconnect{
			HideDisconnectionScreen: false,
			Message:                 s.cfg.Detection.DisconnectMessage,
		})
		conn.Close()
		return
	}

	// Layer 6: max concurrent proxied connections.
	maxConns := int64(s.cfg.Detection.MaxConnections)
	if maxConns > 0 && s.activeConns.Load() >= maxConns {
		conn.WritePacket(&packet.Disconnect{
			HideDisconnectionScreen: false,
			Message:                 "Server is full. Please try again later.",
		})
		conn.Close()
		return
	}

	fpRaw, ok := s.verdicts.LoadAndDelete(identity.Identity)
	if !ok {
		s.emit(ui.Event{
			Type:    ui.EventError,
			Time:    time.Now(),
			Message: fmt.Sprintf("No verdict for %s — dropped", identity.DisplayName),
		})
		conn.Close()
		return
	}
	fp := fpRaw.(*detect.Fingerprint)
	fp.IP = ip

	// Defence in depth — block if verdict survived FetchResourcePacks.
	if fp.Verdict == detect.VerdictBlocked && s.cfg.Detection.BlockOnDetect {
		conn.WritePacket(&packet.Disconnect{
			HideDisconnectionScreen: false,
			Message:                 s.cfg.Detection.DisconnectMessage,
		})
		conn.Close()
		return
	}

	s.emit(ui.Event{
		Type:        ui.EventAllowed,
		Time:        time.Now(),
		Fingerprint: fp,
		ConnID:      connID,
	})
	if s.logger != nil {
		s.logger.LogAllowed(fp)
	}

	s.activeConns.Add(1)
	defer s.activeConns.Add(-1)

	connStart := time.Now()
	spawned := false

	serverConn, err := minecraft.Dialer{
		IdentityData: identity,
		ClientData:   conn.ClientData(),
	}.DialContext(ctx, "raknet", s.cfg.Backend.Address)
	if err != nil {
		errMsg := fmt.Sprintf("backend dial failed for %s: %s", identity.DisplayName, err)
		s.emit(ui.Event{Type: ui.EventError, Time: time.Now(), Message: errMsg})
		if s.logger != nil {
			s.logger.LogError(errMsg)
		}
		conn.WritePacket(&packet.Disconnect{
			HideDisconnectionScreen: false,
			Message:                 "Unable to connect to server. Please try again later.",
		})
		conn.Close()
		return
	}

	if err := serverConn.DoSpawnContext(ctx); err != nil {
		errMsg := fmt.Sprintf("spawn failed for %s: %s", identity.DisplayName, err)
		s.emit(ui.Event{Type: ui.EventError, Time: time.Now(), Message: errMsg})
		if s.logger != nil {
			s.logger.LogError(errMsg)
		}
		serverConn.Close()
		conn.Close()
		return
	}

	if err := conn.StartGame(serverConn.GameData()); err != nil {
		serverConn.Close()
		conn.Close()
		return
	}

	spawned = true

	// Layer 7+9: full behavioral analysis via SessionMetrics.
	// Tracks packet frequency, tick jitter, velocity, and capability bitmask.
	metrics := detect.NewSessionMetrics()

	var wg sync.WaitGroup
	wg.Add(2)

	// Server → Client packet relay.
	go func() {
		defer wg.Done()
		for {
			pk, err := serverConn.ReadPacket()
			if err != nil {
				return
			}
			if err := conn.WritePacket(pk); err != nil {
				return
			}
		}
	}()

	// Client → Server packet relay with deep behavioral tracking.
	go func() {
		defer wg.Done()
		for {
			pk, err := conn.ReadPacket()
			if err != nil {
				return
			}
			switch p := pk.(type) {
			case *packet.PlayerAuthInput:
				metrics.RecordAuthInput(p.Position, p.Tick, p.InputData, p.InputMode)
			case *packet.MovePlayer:
				metrics.RecordMovePlayer()
			case *packet.Interact:
				metrics.RecordInteract()
			case *packet.InventoryTransaction:
				metrics.RecordInventoryTx()
			}
			if err := serverConn.WritePacket(pk); err != nil {
				return
			}
		}
	}()

	wg.Wait()
	serverConn.Close()
	conn.Close()

	sessionDur := time.Since(connStart)

	// Layer 4: grab-and-disconnect — pre-spawn ResourcePackChunkData abort.
	grabTimeout := time.Duration(s.cfg.Detection.GrabDisconnectTimeout) * time.Second
	if !spawned && grabTimeout > 0 && sessionDur < grabTimeout {
		s.emit(ui.Event{
			Type:        ui.EventGrabDisconnect,
			Time:        time.Now(),
			Fingerprint: fp,
			Message:     fmt.Sprintf("%s disconnected before spawn (%.1fs)", identity.DisplayName, sessionDur.Seconds()),
			ConnID:      connID,
		})
		if s.logger != nil {
			s.logger.LogGrabDisconnect(fp)
		}
		s.xuidTracker.RecordBlock(identity.XUID)
		return
	}

	// Layer 7+9: post-session behavioral verdict.
	// Evaluates tick rate, jitter, velocity, capability bitmask, bot patterns.
	if spawned {
		verdict, scoreDelta := metrics.BehaviorVerdict(sessionDur)
		if verdict != "" && scoreDelta > 0 {
			msg := fmt.Sprintf("%s — %s (hz:%.1f jitter:%.1fms vel:%.1f caps:0x%x)",
				identity.DisplayName, verdict,
				metrics.TickRateHz(), metrics.TickJitter(),
				metrics.MaxVelocity(), metrics.Caps)
			s.emit(ui.Event{
				Type:        ui.EventGhostClient,
				Time:        time.Now(),
				Fingerprint: fp,
				Message:     msg,
				ConnID:      connID,
			})
			if s.logger != nil {
				s.logger.LogGhostClient(fp, msg)
			}
			s.xuidTracker.RecordBlock(identity.XUID)
			return
		}
	}

	s.emit(ui.Event{
		Type:    ui.EventDisconnected,
		Time:    time.Now(),
		Message: fmt.Sprintf("%s disconnected after %.0fs (hz:%.1f vel:%.1f caps:0x%x)", identity.DisplayName, sessionDur.Seconds(), metrics.TickRateHz(), metrics.MaxVelocity(), metrics.Caps),
		ConnID:  connID,
	})
}

func (s *Server) emitBlocked(fp *detect.Fingerprint, note string) {
	connID := ConnID(fmt.Sprintf("%s-%d", fp.XUID, time.Now().UnixNano()))
	s.emit(ui.Event{
		Type:        ui.EventBlocked,
		Time:        time.Now(),
		Fingerprint: fp,
		ConnID:      connID,
		Message:     note,
	})
	if s.logger != nil {
		s.logger.LogBlocked(fp)
	}
}

func (s *Server) emit(ev ui.Event) {
	select {
	case s.events <- ev:
	default:
	}
}

// stripDownloadURLs forces chunked RakNet transfer so every byte flows through the proxy.
func stripDownloadURLs(packs []*resource.Pack) []*resource.Pack {
	out := make([]*resource.Pack, len(packs))
	for i, p := range packs {
		if p.DownloadURL() != "" {
			out[i] = p.WithoutDownloadURL()
		} else {
			out[i] = p
		}
	}
	return out
}
