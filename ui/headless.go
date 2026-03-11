// Copyright (c) Savor. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root.

package ui

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"packguard/config"
	"packguard/detect"
)

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiOrange = "\033[38;5;208m"
	ansiDim    = "\033[90m"
	ansiBold   = "\033[1m"
)

func RunHeadless(ctx context.Context, events <-chan Event, listenAddr, backendAddr string) {
	fmt.Printf("\n%s%s  PACKGUARD v%s%s\n", ansiBold, ansiOrange, config.Version, ansiReset)
	fmt.Printf("%s  %s  →  %s%s\n\n", ansiDim, listenAddr, backendAddr, ansiReset)

	var blocked, allowed, total atomic.Int64

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fmt.Printf("%s[%s]  STATS    blocked:%d  allowed:%d  total:%d%s\n",
					ansiDim, time.Now().Format("15:04:05"),
					blocked.Load(), allowed.Load(), total.Load(), ansiReset)
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			fmt.Printf("\n%s[%s]  SHUTDOWN%s\n", ansiDim, time.Now().Format("15:04:05"), ansiReset)
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			ts := ev.Time.Format("15:04:05")

			switch ev.Type {
			case EventBlocked:
				blocked.Add(1)
				total.Add(1)
				score := ""
				if ev.Fingerprint != nil {
					score = fmt.Sprintf("  (score:%.1f)", float64(ev.Fingerprint.TotalScore))
				}
				note := ""
				if ev.Message != "" {
					note = " — " + ev.Message
				}
				fmt.Printf("%s[%s]  BLOCKED  %s  %s%s%s\n",
					ansiRed, ts, fpIdent(ev.Fingerprint), score, note, ansiReset)

			case EventAllowed:
				allowed.Add(1)
				total.Add(1)
				verdict := ""
				if ev.Fingerprint != nil && ev.Fingerprint.Verdict == detect.VerdictSuspicious {
					verdict = fmt.Sprintf("  %s(SUSPICIOUS score:%.1f)%s",
						ansiYellow, float64(ev.Fingerprint.TotalScore), ansiGreen)
				}
				fmt.Printf("%s[%s]  ALLOWED  %s%s%s\n",
					ansiGreen, ts, fpIdent(ev.Fingerprint), verdict, ansiReset)

			case EventRateLimited:
				blocked.Add(1)
				total.Add(1)
				fmt.Printf("%s[%s]  RATE     %s%s\n", ansiYellow, ts, ev.Message, ansiReset)

			case EventGrabDisconnect:
				fmt.Printf("%s[%s]  GRAB     %s%s\n", ansiYellow, ts, ev.Message, ansiReset)

			case EventGhostClient:
				fmt.Printf("%s[%s]  GHOST    %s%s\n", ansiYellow, ts, ev.Message, ansiReset)

			case EventDisconnected:
				fmt.Printf("%s[%s]  DISCONN  %s%s\n", ansiDim, ts, ev.Message, ansiReset)

			case EventError:
				fmt.Printf("%s[%s]  ERROR    %s%s\n", ansiRed, ts, ev.Message, ansiReset)

			case EventProxyStarted:
				fmt.Printf("%s[%s]  INFO     %s%s\n", ansiOrange, ts, ev.Message, ansiReset)
			}
		}
	}
}

func fpIdent(fp *detect.Fingerprint) string {
	if fp == nil {
		return "(unknown)"
	}
	return fmt.Sprintf("%-16s %s", fp.Username, fp.IP)
}
