// Copyright (c) Savor. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root.

package detect

import (
	"math"
	"sync"
	"time"

	"github.com/go-gl/mathgl/mgl32"
)

// Bitwise capability flags — packed into uint64 for O(1) pattern matching.
// Each bit represents an observed client behavior during the session.
const (
	CapSentMovement  uint64 = 1 << iota // Client sent at least one PlayerAuthInput
	CapSentInteract                      // Client sent Interact packet
	CapSentInventory                     // Client sent InventoryTransaction
	CapSprinted                          // InputFlagSprinting was set
	CapJumped                            // InputFlagJumping was set
	CapSneaked                           // InputFlagSneaking was set
	CapSwam                              // InputFlagStartSwimming was set
	CapGlided                            // InputFlagStartGliding was set
	CapEmoted                            // InputFlagEmoting was set
	CapBlockAction                       // InputFlagPerformBlockActions was set
	CapItemInteract                      // InputFlagPerformItemInteraction was set
	CapUsedTouch                         // InputMode == Touch
	CapUsedGamepad                       // InputMode == Gamepad
	CapUsedMouse                         // InputMode == Mouse/KB
	CapTeleported                        // Client acknowledged a teleport
	CapRodeVehicle                       // ClientPredictedVehicle was set
)

// BotPattern is a bitmask fingerprint for known automated clients.
// If (session.Caps & pattern.Mask) == pattern.Expected, it's a match.
type BotPattern struct {
	Name     string
	Mask     uint64
	Expected uint64
}

// KnownBotPatterns are bitmask signatures for common automated clients.
var KnownBotPatterns = []BotPattern{
	{
		Name:     "passive_observer",
		Mask:     CapSentMovement | CapSentInteract | CapSentInventory,
		Expected: 0, // none of these set = zero interaction
	},
	{
		Name:     "input_only_bot",
		Mask:     CapSentMovement | CapSprinted | CapJumped | CapSneaked | CapSentInteract,
		Expected: CapSentMovement, // moves but never sprints/jumps/sneaks/interacts
	},
}

// SessionMetrics tracks per-connection behavioral data for anomaly detection.
type SessionMetrics struct {
	mu sync.Mutex

	Caps     uint64 // bitwise capability flags
	StartAt  time.Time
	LastTick time.Time

	// Packet frequency counters.
	AuthInputCount   int64
	MovePlayerCount  int64
	InteractCount    int64
	InventoryTxCount int64

	// Tick timing for statistical analysis.
	tickIntervals []float64 // ms between consecutive PlayerAuthInput packets
	lastInputTime time.Time

	// Position tracking for velocity validation.
	positions    []timedPos
	maxVelocity  float32
	teleportFlag bool
}

type timedPos struct {
	pos  mgl32.Vec3
	time time.Time
	tick uint64
}

func NewSessionMetrics() *SessionMetrics {
	now := time.Now()
	return &SessionMetrics{
		StartAt:       now,
		LastTick:       now,
		tickIntervals: make([]float64, 0, 256),
		positions:     make([]timedPos, 0, 128),
	}
}

// InputFlag indices from protocol.packet.PlayerAuthInput InputData Bitset.
const (
	flagJumping              = 6
	flagSneaking             = 8
	flagSprinting            = 20
	flagStartSwimming        = 29
	flagStartGliding         = 32
	flagPerformItemInteract  = 34
	flagPerformBlockActions  = 35
	flagHandledTeleport      = 37
	flagEmoting              = 38
)

// InputFlagExtractor reads individual bits from a protocol.Bitset and packs
// them into a uint64 capability mask for O(1) pattern matching.
type InputFlagExtractor struct {
	mapping []struct {
		bitIndex int
		cap      uint64
	}
}

var defaultExtractor = InputFlagExtractor{
	mapping: []struct {
		bitIndex int
		cap      uint64
	}{
		{flagJumping, CapJumped},
		{flagSneaking, CapSneaked},
		{flagSprinting, CapSprinted},
		{flagStartSwimming, CapSwam},
		{flagStartGliding, CapGlided},
		{flagPerformItemInteract, CapItemInteract},
		{flagPerformBlockActions, CapBlockAction},
		{flagHandledTeleport, CapTeleported},
		{flagEmoting, CapEmoted},
	},
}

// Extract reads the Bitset and returns a bitmask of matched capabilities.
func (e *InputFlagExtractor) Extract(loader interface{ Load(int) bool }) uint64 {
	var caps uint64
	for _, m := range e.mapping {
		if loader.Load(m.bitIndex) {
			caps |= m.cap
		}
	}
	return caps
}

// RecordAuthInput processes a PlayerAuthInput packet's behavioral data.
// inputLoader is the InputData Bitset with a Load(int) bool method.
func (s *SessionMetrics) RecordAuthInput(pos mgl32.Vec3, tick uint64, inputLoader interface{ Load(int) bool }, inputMode uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.AuthInputCount++
	s.Caps |= CapSentMovement

	// Track tick intervals for frequency analysis.
	if !s.lastInputTime.IsZero() {
		interval := now.Sub(s.lastInputTime).Seconds() * 1000 // ms
		if len(s.tickIntervals) < 2048 {
			s.tickIntervals = append(s.tickIntervals, interval)
		}
	}
	s.lastInputTime = now
	s.LastTick = now

	// Extract capability flags from InputData bitfield via O(1) bitmask.
	s.Caps |= defaultExtractor.Extract(inputLoader)

	// InputMode capability.
	switch inputMode {
	case 1:
		s.Caps |= CapUsedMouse
	case 2:
		s.Caps |= CapUsedTouch
	case 3:
		s.Caps |= CapUsedGamepad
	}

	// Position tracking for velocity calculation.
	tp := timedPos{pos: pos, time: now, tick: tick}
	if len(s.positions) > 0 {
		prev := s.positions[len(s.positions)-1]
		dt := now.Sub(prev.time).Seconds()
		if dt > 0.001 {
			dx := pos[0] - prev.pos[0]
			dz := pos[2] - prev.pos[2]
			vel := float32(math.Sqrt(float64(dx*dx+dz*dz))) / float32(dt)
			if vel > s.maxVelocity {
				s.maxVelocity = vel
			}
		}
	}

	if len(s.positions) < 512 {
		s.positions = append(s.positions, tp)
	} else {
		copy(s.positions, s.positions[1:])
		s.positions[len(s.positions)-1] = tp
	}
}

func (s *SessionMetrics) RecordInteract()    { s.mu.Lock(); s.Caps |= CapSentInteract; s.InteractCount++; s.mu.Unlock() }
func (s *SessionMetrics) RecordInventoryTx() { s.mu.Lock(); s.Caps |= CapSentInventory; s.InventoryTxCount++; s.mu.Unlock() }
func (s *SessionMetrics) RecordMovePlayer()  { s.mu.Lock(); s.MovePlayerCount++; s.mu.Unlock() }

// TickRateHz returns the average PlayerAuthInput frequency in Hz.
// Bedrock clients send at 20 ticks/sec. Significantly different = suspicious.
func (s *SessionMetrics) TickRateHz() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.AuthInputCount < 2 {
		return 0
	}
	elapsed := s.LastTick.Sub(s.StartAt).Seconds()
	if elapsed < 1 {
		return 0
	}
	return float64(s.AuthInputCount) / elapsed
}

// TickJitter returns the standard deviation of PlayerAuthInput intervals in ms.
// Real clients have consistent ~50ms intervals. Bots often have erratic or
// perfectly uniform timing.
func (s *SessionMetrics) TickJitter() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := len(s.tickIntervals)
	if n < 10 {
		return -1 // not enough data
	}

	// Mean.
	var sum float64
	for _, v := range s.tickIntervals {
		sum += v
	}
	mean := sum / float64(n)

	// Variance.
	var variance float64
	for _, v := range s.tickIntervals {
		d := v - mean
		variance += d * d
	}
	variance /= float64(n)

	return math.Sqrt(variance)
}

// MaxVelocity returns the highest observed horizontal velocity in blocks/sec.
// Bedrock sprint speed is ~5.6 b/s, sprint-jump ~7.1 b/s. Anything above
// ~15 b/s without a teleport is suspicious.
func (s *SessionMetrics) MaxVelocity() float32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxVelocity
}

// MatchBotPatterns checks session capabilities against known bot bitmask signatures.
func (s *SessionMetrics) MatchBotPatterns() []BotPattern {
	s.mu.Lock()
	caps := s.Caps
	s.mu.Unlock()

	var matches []BotPattern
	for _, p := range KnownBotPatterns {
		if (caps & p.Mask) == p.Expected {
			matches = append(matches, p)
		}
	}
	return matches
}

// BehaviorVerdict evaluates post-session behavioral metrics and returns a
// verdict string and score delta. Called after the packet relay ends.
func (s *SessionMetrics) BehaviorVerdict(sessionDur time.Duration) (verdict string, scoreDelta Score) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sessionDur < 10*time.Second {
		return "", 0
	}

	// Ghost client: spawned but zero input packets.
	if s.AuthInputCount == 0 {
		return "ghost_client: zero PlayerAuthInput packets", 10.0
	}

	// Tick rate anomaly: Bedrock sends 20 ticks/sec.
	elapsed := s.LastTick.Sub(s.StartAt).Seconds()
	if elapsed > 5 {
		hz := float64(s.AuthInputCount) / elapsed
		if hz < 5 {
			return "low_tick_rate: PlayerAuthInput below 5 Hz", 5.0
		}
		if hz > 40 {
			return "high_tick_rate: PlayerAuthInput above 40 Hz", 5.0
		}
	}

	// Zero jitter = programmatic packet generation.
	if len(s.tickIntervals) > 30 {
		var sum float64
		for _, v := range s.tickIntervals {
			sum += v
		}
		mean := sum / float64(len(s.tickIntervals))

		var variance float64
		for _, v := range s.tickIntervals {
			d := v - mean
			variance += d * d
		}
		variance /= float64(len(s.tickIntervals))
		stddev := math.Sqrt(variance)

		if stddev < 0.5 && mean > 10 {
			return "zero_jitter: perfectly uniform tick timing (bot)", 4.0
		}
	}

	// Velocity anomaly: > 20 b/s without a teleport is impossible.
	if s.maxVelocity > 20 && (s.Caps&CapTeleported == 0) {
		return "speed_anomaly: velocity exceeds 20 b/s without teleport", 6.0
	}

	// Bot pattern matching via bitmask.
	caps := s.Caps
	for _, p := range KnownBotPatterns {
		if (caps&p.Mask) == p.Expected && sessionDur > 30*time.Second {
			return "bot_pattern: " + p.Name, 3.0
		}
	}

	return "", 0
}
