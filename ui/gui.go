// Copyright (c) Savor. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root.

package ui

import (
	"context"
	"fmt"
	"image/color"
	"sync"
	"time"

	"packguard/detect"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

const maxLogEntries = 500

var (
	colorAccent = color.NRGBA{R: 255, G: 107, B: 53, A: 255}
	colorDim    = color.NRGBA{R: 102, G: 102, B: 102, A: 255}
)

type ConnectionEntry struct {
	Index       int
	Username    string
	IP          string
	Verdict     detect.Verdict
	Time        time.Time
	Fingerprint *detect.Fingerprint
}

type GUI struct {
	mu          sync.Mutex
	ctx         context.Context
	events      <-chan Event
	connections []ConnectionEntry
	selectedIdx int
	listenAddr  string
	backendAddr string
	startTime   time.Time

	blocked int
	allowed int
	total   int

	connList    *widget.List
	detailPanel *fyne.Container
	logText     *widget.RichText
	statsLabel  *widget.Label
	uptimeLabel *widget.Label
	window      fyne.Window
}

func NewGUI(ctx context.Context, events <-chan Event, listenAddr, backendAddr string) *GUI {
	return &GUI{
		ctx:         ctx,
		events:      events,
		listenAddr:  listenAddr,
		backendAddr: backendAddr,
		startTime:   time.Now(),
	}
}

func (g *GUI) Build(w fyne.Window) fyne.CanvasObject {
	g.window = w

	g.connList = widget.NewList(
		func() int {
			g.mu.Lock()
			defer g.mu.Unlock()
			return len(g.connections)
		},
		func() fyne.CanvasObject {
			return container.NewHBox(
				widget.NewLabel("000"),
				widget.NewLabel("Username________"),
				widget.NewLabel("000.000.000.000"),
				widget.NewLabel("BLOCKED"),
				widget.NewLabel("00:00"),
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			g.mu.Lock()
			if id >= len(g.connections) {
				g.mu.Unlock()
				return
			}
			c := g.connections[id]
			g.mu.Unlock()

			box := obj.(*fyne.Container)
			box.Objects[0].(*widget.Label).SetText(fmt.Sprintf("%d", c.Index))
			box.Objects[1].(*widget.Label).SetText(truncate(c.Username, 16))
			box.Objects[2].(*widget.Label).SetText(truncate(c.IP, 15))

			verdictLabel := box.Objects[3].(*widget.Label)
			switch c.Verdict {
			case detect.VerdictBlocked:
				verdictLabel.SetText("BLOCKED")
			case detect.VerdictSuspicious:
				verdictLabel.SetText("SUSPICIOUS")
			default:
				verdictLabel.SetText("OK")
			}

			box.Objects[4].(*widget.Label).SetText(c.Time.Format("15:04"))
		},
	)
	g.connList.OnSelected = func(id widget.ListItemID) {
		g.mu.Lock()
		g.selectedIdx = id
		g.mu.Unlock()
		g.refreshDetail()
	}

	g.detailPanel = container.NewVBox()
	g.refreshDetail()

	g.logText = widget.NewRichText()
	g.logText.Wrapping = fyne.TextWrapWord

	logScroll := container.NewVScroll(g.logText)
	logScroll.SetMinSize(fyne.NewSize(0, 150))

	g.statsLabel = widget.NewLabel("Blocked: 0  Allowed: 0  Total: 0")
	g.uptimeLabel = widget.NewLabel("Uptime: 00:00:00")

	titleText := canvas.NewText("PACKGUARD", colorAccent)
	titleText.TextStyle.Bold = true
	titleText.TextSize = 18

	addrText := canvas.NewText(
		fmt.Sprintf("%s  ->  %s", g.listenAddr, g.backendAddr),
		colorDim,
	)
	addrText.TextSize = 12

	titleBar := container.NewHBox(titleText, addrText)

	connLabel := widget.NewLabelWithStyle("CONNECTIONS", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	detailLabel := widget.NewLabelWithStyle("FINGERPRINT ANALYSIS", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	logLabel := widget.NewLabelWithStyle("EVENT LOG", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	detailScroll := container.NewVScroll(g.detailPanel)
	detailScroll.SetMinSize(fyne.NewSize(350, 0))

	leftPanel := container.NewBorder(connLabel, nil, nil, nil, g.connList)
	rightPanel := container.NewBorder(detailLabel, nil, nil, nil, detailScroll)

	topSplit := container.NewHSplit(leftPanel, rightPanel)
	topSplit.SetOffset(0.45)

	logPanel := container.NewBorder(logLabel, nil, nil, nil, logScroll)

	mainSplit := container.NewVSplit(topSplit, logPanel)
	mainSplit.SetOffset(0.65)

	statsBar := container.NewHBox(g.statsLabel, g.uptimeLabel)

	go g.pollEvents()
	go g.tickUptime()

	return container.NewBorder(titleBar, statsBar, nil, nil, mainSplit)
}

func (g *GUI) pollEvents() {
	for ev := range g.events {
		g.handleEvent(ev)
	}
}

func (g *GUI) handleEvent(ev Event) {
	g.mu.Lock()
	switch ev.Type {
	case EventBlocked:
		entry := ConnectionEntry{
			Index:       g.total + 1,
			Username:    ev.Fingerprint.Username,
			IP:          ev.Fingerprint.IP,
			Verdict:     detect.VerdictBlocked,
			Time:        ev.Time,
			Fingerprint: ev.Fingerprint,
		}
		g.connections = append([]ConnectionEntry{entry}, g.connections...)
		if len(g.connections) > 50 {
			g.connections = g.connections[:50]
		}
		g.blocked++
		g.total++
		g.mu.Unlock()

		note := ""
		if ev.Message != "" {
			note = " — " + ev.Message
		}
		g.addLogEntry(ev.Time, "BLOCKED", fmt.Sprintf("%s  %s  (score:%.1f)%s",
			ev.Fingerprint.Username, ev.Fingerprint.IP, float64(ev.Fingerprint.TotalScore), note), theme.ColorNameError)

	case EventAllowed:
		entry := ConnectionEntry{
			Index:       g.total + 1,
			Username:    ev.Fingerprint.Username,
			IP:          ev.Fingerprint.IP,
			Verdict:     ev.Fingerprint.Verdict,
			Time:        ev.Time,
			Fingerprint: ev.Fingerprint,
		}
		g.connections = append([]ConnectionEntry{entry}, g.connections...)
		if len(g.connections) > 50 {
			g.connections = g.connections[:50]
		}
		g.allowed++
		g.total++
		g.mu.Unlock()
		g.addLogEntry(ev.Time, "ALLOWED", fmt.Sprintf("%s  %s",
			ev.Fingerprint.Username, ev.Fingerprint.IP), theme.ColorNameSuccess)

	case EventRateLimited:
		g.blocked++
		g.total++
		g.mu.Unlock()
		g.addLogEntry(ev.Time, "RATE", ev.Message, theme.ColorNameWarning)

	case EventGrabDisconnect:
		g.mu.Unlock()
		g.addLogEntry(ev.Time, "GRAB", ev.Message, theme.ColorNameWarning)

	case EventGhostClient:
		g.mu.Unlock()
		g.addLogEntry(ev.Time, "GHOST", ev.Message, theme.ColorNameWarning)

	case EventDisconnected:
		g.mu.Unlock()
		g.addLogEntry(ev.Time, "DISCONN", ev.Message, theme.ColorNameDisabled)

	case EventError:
		g.mu.Unlock()
		g.addLogEntry(ev.Time, "ERROR", ev.Message, theme.ColorNameError)

	case EventProxyStarted:
		g.mu.Unlock()
		g.addLogEntry(ev.Time, "INFO", ev.Message, theme.ColorNamePrimary)

	default:
		g.mu.Unlock()
	}

	g.connList.Refresh()
	g.refreshDetail()
	g.refreshStats()
}

func (g *GUI) addLogEntry(t time.Time, tag, msg string, colorName fyne.ThemeColorName) {
	ts := t.Format("15:04:05")
	line := fmt.Sprintf("[%s]  %-7s  %s", ts, tag, msg)
	seg := &widget.TextSegment{
		Text: line + "\n",
		Style: widget.RichTextStyle{
			ColorName: colorName,
			TextStyle: fyne.TextStyle{Monospace: true},
		},
	}

	if len(g.logText.Segments) >= maxLogEntries {
		g.logText.Segments = g.logText.Segments[len(g.logText.Segments)-maxLogEntries/2:]
	}
	g.logText.Segments = append(g.logText.Segments, seg)
	g.logText.Refresh()
}

func (g *GUI) refreshDetail() {
	g.mu.Lock()
	var fp *detect.Fingerprint
	if g.selectedIdx < len(g.connections) {
		fp = g.connections[g.selectedIdx].Fingerprint
	}
	g.mu.Unlock()

	g.detailPanel.Objects = nil

	if fp == nil {
		g.detailPanel.Add(widget.NewLabel("No connection selected"))
		g.detailPanel.Refresh()
		return
	}

	g.detailPanel.Add(widget.NewLabelWithStyle("IDENTITY", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}))
	g.detailPanel.Add(newFieldRow("Username", fp.Username))
	g.detailPanel.Add(newFieldRow("XUID", fp.XUID))
	g.detailPanel.Add(newFieldRow("IP", fp.IP))
	g.detailPanel.Add(newFieldRow("Version", fp.GameVersion))
	g.detailPanel.Add(newFieldRow("Language", fp.LanguageCode))
	g.detailPanel.Add(widget.NewSeparator())

	g.detailPanel.Add(widget.NewLabelWithStyle("DEVICE DATA", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}))
	g.detailPanel.Add(newFieldRow("OS", detect.DeviceOSName(fp.DeviceOS)))
	g.detailPanel.Add(newFieldRow("Model", orEmpty(fp.DeviceModel)))
	g.detailPanel.Add(newFieldRow("Device ID", orEmpty(fp.DeviceID)))
	g.detailPanel.Add(newFieldRow("UI Profile", detect.UIProfileName(fp.UIProfile)))
	g.detailPanel.Add(newFieldRow("Input Mode", detect.InputModeName(fp.InputMode)))
	g.detailPanel.Add(newFieldRow("Platform ID", orEmpty(fp.PlatformOnlineID)))
	g.detailPanel.Add(newFieldRow("Memory Tier", fmt.Sprintf("%d", fp.MemoryTier)))
	g.detailPanel.Add(newFieldRow("Skin ID", orEmpty(fp.SkinID)))
	g.detailPanel.Add(newFieldRow("Trusted Skin", fmt.Sprintf("%v", fp.TrustedSkin)))
	g.detailPanel.Add(widget.NewSeparator())

	suspicious := fp.SuspiciousSignals()
	if len(suspicious) > 0 {
		g.detailPanel.Add(widget.NewLabelWithStyle("DETECTION SIGNALS", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}))
		for _, s := range suspicious {
			row := fmt.Sprintf("%-16s %-12s +%.1f", s.Name, s.RawValue, float64(s.Score))
			g.detailPanel.Add(widget.NewLabelWithStyle(row, fyne.TextAlignLeading, fyne.TextStyle{Monospace: true}))
		}
		g.detailPanel.Add(widget.NewSeparator())

		scoreStr := fmt.Sprintf("Total Score: %.1f  ->  %s", float64(fp.TotalScore), fp.Verdict)
		scoreLabel := widget.NewLabelWithStyle(scoreStr, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
		g.detailPanel.Add(scoreLabel)
	} else {
		g.detailPanel.Add(widget.NewLabel("No suspicious signals"))
	}

	g.detailPanel.Refresh()
}

func (g *GUI) refreshStats() {
	g.mu.Lock()
	b, a, t := g.blocked, g.allowed, g.total
	g.mu.Unlock()
	g.statsLabel.SetText(fmt.Sprintf("Blocked: %d   Allowed: %d   Total: %d", b, a, t))
}

func (g *GUI) tickUptime() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-g.ctx.Done():
			return
		case <-ticker.C:
			uptime := time.Since(g.startTime).Truncate(time.Second)
			h := int(uptime.Hours())
			m := int(uptime.Minutes()) % 60
			s := int(uptime.Seconds()) % 60
			g.uptimeLabel.SetText(fmt.Sprintf("Uptime: %02d:%02d:%02d", h, m, s))
		}
	}
}

func newFieldRow(label, value string) fyne.CanvasObject {
	l := widget.NewLabelWithStyle(label, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	l.Wrapping = fyne.TextTruncate
	v := widget.NewLabel(value)
	v.Wrapping = fyne.TextTruncate
	return container.NewGridWithColumns(2, l, v)
}

func orEmpty(s string) string {
	if s == "" {
		return "(empty)"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

type packguardTheme struct {
	fyne.Theme
}

func NewPackguardTheme() fyne.Theme {
	return &packguardTheme{Theme: theme.DarkTheme()}
}

func (t *packguardTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.NRGBA{R: 13, G: 13, B: 13, A: 255}
	case theme.ColorNameForeground:
		return color.NRGBA{R: 221, G: 221, B: 221, A: 255}
	case theme.ColorNamePrimary:
		return colorAccent
	}
	return t.Theme.Color(name, variant)
}
