// Copyright (c) Savor. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root.

package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"packguard/detect"
)

const maxLogLines = 10000

type LogEntry struct {
	Timestamp string   `json:"ts"`
	Event     string   `json:"event"`
	Username  string   `json:"user,omitempty"`
	XUID      string   `json:"xuid,omitempty"`
	IP        string   `json:"ip,omitempty"`
	Score     float64  `json:"score,omitempty"`
	Signals   []string `json:"signals,omitempty"`
	OS        string   `json:"os,omitempty"`
	Model     string   `json:"model,omitempty"`
	Message   string   `json:"message,omitempty"`
}

type FileLogger struct {
	mu      sync.Mutex
	file    *os.File
	path    string
	lines   int
	verbose bool
}

func NewFileLogger(path string, verbose bool) (*FileLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return &FileLogger{file: f, path: path, verbose: verbose}, nil
}

func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

func (l *FileLogger) LogBlocked(fp *detect.Fingerprint) {
	var sigs []string
	for _, s := range fp.SuspiciousSignals() {
		sigs = append(sigs, s.Name)
	}
	l.writeEntry(LogEntry{
		Event:    "blocked",
		Username: fp.Username,
		XUID:     fp.XUID,
		IP:       fp.IP,
		Score:    float64(fp.TotalScore),
		Signals:  sigs,
		OS:       detect.DeviceOSName(fp.DeviceOS),
		Model:    fp.DeviceModel,
	})
}

func (l *FileLogger) LogAllowed(fp *detect.Fingerprint) {
	if !l.verbose {
		return
	}
	l.writeEntry(LogEntry{
		Event:    "allowed",
		Username: fp.Username,
		XUID:     fp.XUID,
		IP:       fp.IP,
		OS:       detect.DeviceOSName(fp.DeviceOS),
		Model:    fp.DeviceModel,
	})
}

func (l *FileLogger) LogRateLimited(ip string) {
	l.writeEntry(LogEntry{
		Event:   "rate_limited",
		IP:      ip,
		Message: "connection rate exceeded",
	})
}

func (l *FileLogger) LogGrabDisconnect(fp *detect.Fingerprint) {
	l.writeEntry(LogEntry{
		Event:    "grab_disconnect",
		Username: fp.Username,
		XUID:     fp.XUID,
		IP:       fp.IP,
	})
}

func (l *FileLogger) LogGhostClient(fp *detect.Fingerprint, msg string) {
	l.writeEntry(LogEntry{
		Event:    "ghost_client",
		Username: fp.Username,
		XUID:     fp.XUID,
		IP:       fp.IP,
		Message:  msg,
	})
}

func (l *FileLogger) LogPackServed(xuid, username, packUUID, contentKey string) {
	l.writeEntry(LogEntry{
		Event:    "pack_served",
		XUID:     xuid,
		Username: username,
		Message:  fmt.Sprintf("pack:%s key:%s", packUUID, contentKey),
	})
}

func (l *FileLogger) LogError(msg string) {
	l.writeEntry(LogEntry{
		Event:   "error",
		Message: msg,
	})
}

func (l *FileLogger) writeEntry(entry LogEntry) {
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)

	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	l.file.Write(append(data, '\n'))
	l.lines++

	// Rotate: truncate at cap to avoid external log rotation.
	if l.lines >= maxLogLines {
		l.file.Truncate(0)
		l.file.Seek(0, 0)
		l.lines = 0
	}
}
