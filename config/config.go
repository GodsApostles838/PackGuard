// Copyright (c) Savor. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root.

package config

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

const Version = "1.0.0"

type Config struct {
	Listen       string          `yaml:"listen"`
	AuthDisabled bool            `yaml:"auth_disabled"`
	Backend      BackendConfig   `yaml:"backend"`
	Detection    DetectionConfig `yaml:"detection"`
	Log          LogConfig       `yaml:"log"`

	whitelistSet map[string]bool `yaml:"-"`
}

type BackendConfig struct {
	Address string `yaml:"address"`
}

type DetectionConfig struct {
	Threshold             float64  `yaml:"threshold"`
	BlockOnDetect         bool     `yaml:"block_on_detect"`
	DisconnectMessage     string   `yaml:"disconnect_message"`
	RateLimit             int      `yaml:"rate_limit"`
	MaxConnections        int      `yaml:"max_connections"`
	RepeatBlockCount      int      `yaml:"repeat_block_count"`
	GrabDisconnectTimeout int      `yaml:"grab_disconnect_timeout"`
	EncryptPacks          bool     `yaml:"encrypt_packs"`
	Whitelist             []string `yaml:"whitelist"`
}

type LogConfig struct {
	File    string `yaml:"file"`
	Verbose bool   `yaml:"verbose"`
}

func Default() *Config {
	return &Config{
		Listen: "0.0.0.0:19132",
		Backend: BackendConfig{
			Address: "127.0.0.1:19133",
		},
		Detection: DetectionConfig{
			Threshold:             5.0,
			BlockOnDetect:         true,
			DisconnectMessage:     "Unable to connect to server. Please try again later.",
			RateLimit:             5,
			MaxConnections:        100,
			RepeatBlockCount:      3,
			GrabDisconnectTimeout: 30,
		},
		Log: LogConfig{
			File:    "packguard.log",
			Verbose: false,
		},
	}
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	cfg.buildWhitelist()
	return cfg, nil
}

func WriteDefault(path string) error {
	data, err := yaml.Marshal(Default())
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (c *Config) Validate() error {
	if c.Detection.Threshold <= 0 {
		return fmt.Errorf("detection.threshold must be > 0, got %.1f", c.Detection.Threshold)
	}
	if c.Listen == "" {
		return fmt.Errorf("listen address cannot be empty")
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen address %q is invalid: %w", c.Listen, err)
	}
	if c.Backend.Address == "" {
		return fmt.Errorf("backend.address cannot be empty")
	}
	if _, _, err := net.SplitHostPort(c.Backend.Address); err != nil {
		return fmt.Errorf("backend.address %q is invalid: %w", c.Backend.Address, err)
	}
	return nil
}

func (c *Config) IsWhitelisted(xuid string) bool {
	if c.whitelistSet == nil {
		c.buildWhitelist()
	}
	return c.whitelistSet[xuid]
}

func (c *Config) buildWhitelist() {
	c.whitelistSet = make(map[string]bool, len(c.Detection.Whitelist))
	for _, x := range c.Detection.Whitelist {
		c.whitelistSet[x] = true
	}
}
