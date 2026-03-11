// Copyright (c) Savor. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"packguard/config"
	"packguard/proxy"
	"packguard/ui"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
)

func main() {
	version := flag.Bool("version", false, "print version and exit")
	headless := flag.Bool("headless", false, "run without GUI (for hosting servers)")
	configPath := flag.String("config", "packguard.yaml", "path to YAML config file")
	flag.Parse()

	if *version {
		fmt.Printf("PackGuard v%s\n", config.Version)
		os.Exit(0)
	}

	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		if err := config.WriteDefault(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "fatal: write default config: %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("Default config written to %s — edit it, then run PackGuard again.\n", *configPath)
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: load config: %s\n", err)
		os.Exit(1)
	}

	events := make(chan ui.Event, 256)

	var logger *proxy.FileLogger
	if cfg.Log.File != "" {
		logger, err = proxy.NewFileLogger(cfg.Log.File, cfg.Log.Verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fatal: open log file: %s\n", err)
			os.Exit(1)
		}
		defer logger.Close()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	srv := proxy.NewServer(cfg, events, logger)

	if *headless {
		go func() {
			if err := srv.Run(ctx); err != nil {
				events <- ui.Event{
					Type:    ui.EventError,
					Time:    time.Now(),
					Message: fmt.Sprintf("proxy stopped: %s", err),
				}
				cancel()
			}
		}()
		ui.RunHeadless(ctx, events, cfg.Listen, cfg.Backend.Address)
		return
	}

	go func() {
		if err := srv.Run(ctx); err != nil {
			events <- ui.Event{
				Type:    ui.EventError,
				Time:    time.Now(),
				Message: fmt.Sprintf("proxy stopped: %s", err),
			}
		}
	}()

	a := app.New()
	a.Settings().SetTheme(ui.NewPackguardTheme())

	w := a.NewWindow("PackGuard")
	w.Resize(fyne.NewSize(1000, 700))
	w.SetContent(ui.NewGUI(ctx, events, cfg.Listen, cfg.Backend.Address).Build(w))
	w.SetCloseIntercept(func() {
		cancel()
		w.Close()
	})

	w.ShowAndRun()
}
