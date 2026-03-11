// Copyright (c) Savor. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root.

package proxy

import (
	"sync"
	"time"
)

// RateLimiter tracks per-IP connection attempts using a sliding window.
type RateLimiter struct {
	mu      sync.Mutex
	window  time.Duration
	limit   int
	entries map[string][]time.Time
}

func NewRateLimiter(limit int) *RateLimiter {
	return &RateLimiter{
		window:  time.Minute,
		limit:   limit,
		entries: make(map[string][]time.Time),
	}
}

func (r *RateLimiter) Allow(ip string) bool {
	if r.limit <= 0 {
		return true
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-r.window)

	timestamps := r.entries[ip]
	valid := timestamps[:0]
	for _, t := range timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= r.limit {
		r.entries[ip] = valid
		return false
	}

	r.entries[ip] = append(valid, now)
	return true
}

func (r *RateLimiter) Cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := time.Now().Add(-r.window)
	for ip, timestamps := range r.entries {
		valid := timestamps[:0]
		for _, t := range timestamps {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(r.entries, ip)
		} else {
			r.entries[ip] = valid
		}
	}
}

// XUIDTracker auto-blocks repeat offenders after N strikes.
type XUIDTracker struct {
	mu      sync.Mutex
	strikes map[string]int
	blocked map[string]time.Time
	maxHits int
	banTime time.Duration
}

func NewXUIDTracker(maxHits int) *XUIDTracker {
	return &XUIDTracker{
		strikes: make(map[string]int),
		blocked: make(map[string]time.Time),
		maxHits: maxHits,
		banTime: time.Hour,
	}
}

func (t *XUIDTracker) RecordBlock(xuid string) bool {
	if t.maxHits <= 0 || xuid == "" {
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	t.strikes[xuid]++
	if t.strikes[xuid] >= t.maxHits {
		t.blocked[xuid] = time.Now().Add(t.banTime)
		return true
	}
	return false
}

func (t *XUIDTracker) IsBlocked(xuid string) bool {
	if t.maxHits <= 0 || xuid == "" {
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	expiry, ok := t.blocked[xuid]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(t.blocked, xuid)
		delete(t.strikes, xuid)
		return false
	}
	return true
}
