// Copyright (c) Savor. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root.

package detect

import (
	"fmt"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
)

type Score float64

type Verdict string

const (
	VerdictClean      Verdict = "CLEAN"
	VerdictSuspicious Verdict = "SUSPICIOUS"
	VerdictBlocked    Verdict = "BLOCKED"
)

func (v Verdict) String() string { return string(v) }

type Signal struct {
	Name       string
	RawValue   string
	Score      Score
	Suspicious bool
	Reason     string
}

type Fingerprint struct {
	XUID     string
	Username string
	UUID     string
	IP       string

	DeviceOS         protocol.DeviceOS
	DeviceModel      string
	DeviceID         string
	UIProfile        int
	InputMode        int
	DefaultInput     int
	GameVersion      string
	GUIScale         int
	PlatformOnlineID string
	LanguageCode     string
	SelfSignedID     string
	SkinID           string
	TrustedSkin      bool
	MemoryTier       int

	Signals    []Signal
	TotalScore Score
	Verdict    Verdict

	ConnectedAt time.Time
}

func DeviceOSName(os protocol.DeviceOS) string {
	switch os {
	case protocol.DeviceAndroid:
		return "Android"
	case protocol.DeviceIOS:
		return "iOS"
	case protocol.DeviceOSX:
		return "macOS"
	case protocol.DeviceFireOS:
		return "FireOS"
	case protocol.DeviceGearVR:
		return "GearVR"
	case protocol.DeviceHololens:
		return "HoloLens"
	case protocol.DeviceWin10:
		return "Windows"
	case protocol.DeviceWin32:
		return "Win32"
	case protocol.DeviceDedicated:
		return "Dedicated"
	case protocol.DeviceTVOS:
		return "tvOS"
	case protocol.DeviceOrbis:
		return "PlayStation"
	case protocol.DeviceNX:
		return "Switch"
	case protocol.DeviceXBOX:
		return "Xbox"
	case protocol.DeviceWP:
		return "WindowsPhone"
	case protocol.DeviceLinux:
		return "Linux"
	default:
		return fmt.Sprintf("Unknown(%d)", os)
	}
}

func UIProfileName(p int) string {
	if p == 0 {
		return "Classic"
	}
	return "Pocket"
}

func InputModeName(m int) string {
	switch m {
	case 1:
		return "Mouse/KB"
	case 2:
		return "Touch"
	case 3:
		return "Gamepad"
	default:
		return fmt.Sprintf("Unknown(%d)", m)
	}
}

// Analyze scores a client's login.IdentityData and login.ClientData against
// all detection heuristics. Threshold sets the BLOCKED boundary.
func Analyze(identity login.IdentityData, client login.ClientData, threshold Score) *Fingerprint {
	fp := &Fingerprint{
		XUID:             identity.XUID,
		Username:         identity.DisplayName,
		UUID:             identity.Identity,
		DeviceOS:         client.DeviceOS,
		DeviceModel:      client.DeviceModel,
		DeviceID:         string(client.DeviceID),
		UIProfile:        client.UIProfile,
		InputMode:        client.CurrentInputMode,
		DefaultInput:     client.DefaultInputMode,
		GameVersion:      client.GameVersion,
		GUIScale:         client.GUIScale,
		PlatformOnlineID: client.PlatformOnlineID,
		LanguageCode:     client.LanguageCode,
		SelfSignedID:     client.SelfSignedID,
		SkinID:           client.SkinID,
		TrustedSkin:      client.TrustedSkin,
		MemoryTier:       client.MemoryTier,
		ConnectedAt:      time.Now(),
	}

	isAndroid := client.DeviceOS == protocol.DeviceAndroid

	// --- ClientData device fields ---

	if isAndroid && client.DeviceModel == "" {
		fp.addSignal("Device Model", "\"\"", 4.0, true, "Android device with empty model — gophertunnel default")
	} else {
		fp.addSignal("Device Model", client.DeviceModel, 0, false, "")
	}

	if isAndroid && client.UIProfile == 0 {
		fp.addSignal("UI Profile", "Classic", 2.0, true, "Android with Classic UI — impossible on real mobile")
	} else {
		fp.addSignal("UI Profile", UIProfileName(client.UIProfile), 0, false, "")
	}

	if isAndroid && (client.CurrentInputMode == 1 || client.DefaultInputMode == 1) {
		fp.addSignal("Input Mode", "Mouse/KB", 2.0, true, "Android with Mouse/KB — gophertunnel default")
	} else {
		fp.addSignal("Input Mode", InputModeName(client.CurrentInputMode), 0, false, "")
	}

	if client.PlatformOnlineID == "" {
		fp.addSignal("Platform ID", "(empty)", 1.0, true, "Missing PlatformOnlineID")
	} else {
		fp.addSignal("Platform ID", client.PlatformOnlineID, 0, false, "")
	}

	if client.DeviceOS == 0 {
		fp.addSignal("Device OS", "Unknown(0)", 3.0, true, "No legitimate client sends DeviceOS=0")
	}

	if client.DeviceOS == protocol.DeviceDedicated {
		fp.addSignal("Device OS", "Dedicated", 5.0, true, "Client claiming DeviceOS=Dedicated")
	}

	if client.GUIScale != 0 && client.GUIScale != -1 && client.GUIScale != -2 {
		fp.addSignal("GUI Scale", fmt.Sprintf("%d", client.GUIScale), 0.5, true, "Unusual GUIScale")
	} else {
		fp.addSignal("GUI Scale", fmt.Sprintf("%d", client.GUIScale), 0, false, "")
	}

	if client.LanguageCode == "" {
		fp.addSignal("Language", "(empty)", 0.5, true, "Empty LanguageCode")
	} else {
		fp.addSignal("Language", client.LanguageCode, 0, false, "")
	}

	// --- IdentityData fields ---

	if identity.XUID == "" {
		fp.addSignal("XUID", "(empty)", 2.0, true, "No Xbox Live XUID — unauthenticated")
	} else {
		fp.addSignal("XUID", identity.XUID, 0, false, "")
	}

	if identity.DisplayName == "" {
		fp.addSignal("Display Name", "(empty)", 1.0, true, "Empty DisplayName")
	}

	// --- ClientData skin fields ---

	if client.SkinImageHeight == 0 || client.SkinImageWidth == 0 {
		fp.addSignal("Skin Size", "0x0", 2.0, true, "Zero SkinImageWidth/Height")
	}

	if client.SkinData == "" {
		fp.addSignal("Skin Data", "(empty)", 2.0, true, "Empty SkinData — no RGBA payload")
	}

	if !client.TrustedSkin {
		fp.addSignal("Trusted Skin", "false", 1.0, true, "TrustedSkin=false — not Xbox Live validated")
	}

	// --- ClientData identity fields ---

	if string(client.DeviceID) == "" {
		fp.addSignal("Device ID", "(empty)", 1.5, true, "Missing DeviceID")
	}

	if client.SelfSignedID == "" {
		fp.addSignal("SelfSigned ID", "(empty)", 1.0, true, "Missing SelfSignedID")
	}

	if isAndroid && client.MemoryTier == 0 {
		fp.addSignal("Memory Tier", "0", 1.0, true, "Android with MemoryTier=0 — gophertunnel default")
	}

	// Verdict: BLOCKED at threshold, SUSPICIOUS at 60%.
	if fp.TotalScore >= threshold {
		fp.Verdict = VerdictBlocked
	} else if fp.TotalScore >= threshold*0.6 {
		fp.Verdict = VerdictSuspicious
	} else {
		fp.Verdict = VerdictClean
	}

	return fp
}

func (fp *Fingerprint) addSignal(name, rawValue string, score Score, suspicious bool, reason string) {
	fp.Signals = append(fp.Signals, Signal{
		Name:       name,
		RawValue:   rawValue,
		Score:      score,
		Suspicious: suspicious,
		Reason:     reason,
	})
	fp.TotalScore += score
}

func (fp *Fingerprint) SuspiciousSignals() []Signal {
	var out []Signal
	for _, s := range fp.Signals {
		if s.Suspicious {
			out = append(out, s)
		}
	}
	return out
}
