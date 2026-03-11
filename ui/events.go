// Copyright (c) Savor. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root.

package ui

import (
	"time"

	"packguard/detect"
)

type EventType int

const (
	EventBlocked        EventType = iota
	EventAllowed
	EventDisconnected
	EventError
	EventProxyStarted
	EventRateLimited
	EventGrabDisconnect
	EventGhostClient
)

type Event struct {
	Type        EventType
	Time        time.Time
	Fingerprint *detect.Fingerprint
	Message     string
	ConnID      string
}
