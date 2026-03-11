// Copyright (c) Savor. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root.

package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/resource"
)

const ContentKeyLength = 32

type PackSignature struct {
	UUID    string
	Name    string
	Version string
	SHA256  string
	Size    int
	HasKey  bool
}

type KeyDistribution struct {
	XUID       string
	Username   string
	PackUUID   string
	ContentKey string
	Time       time.Time
}

// PackTracker monitors resource pack distribution and content key assignment.
type PackTracker struct {
	mu             sync.Mutex
	signatures     []PackSignature
	distributions  []KeyDistribution
	generatedKeys  map[string]string
	encryptEnabled bool
}

func NewPackTracker(encrypt bool) *PackTracker {
	return &PackTracker{
		generatedKeys:  make(map[string]string),
		encryptEnabled: encrypt,
	}
}

func (pt *PackTracker) ComputeSignatures(packs []*resource.Pack) []PackSignature {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	pt.signatures = make([]PackSignature, 0, len(packs))
	for _, p := range packs {
		sig := PackSignature{
			UUID:    p.UUID().String(),
			Name:    p.Name(),
			Version: p.Version(),
			SHA256:  fmt.Sprintf("%x", p.Checksum()),
			Size:    p.Len(),
			HasKey:  p.Encrypted(),
		}
		pt.signatures = append(pt.signatures, sig)
	}
	return pt.signatures
}

func (pt *PackTracker) Signatures() []PackSignature {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	out := make([]PackSignature, len(pt.signatures))
	copy(out, pt.signatures)
	return out
}

// ApplyContentKeys generates AES-256 content keys via TexturePackInfo.ContentKey.
func (pt *PackTracker) ApplyContentKeys(packs []*resource.Pack) []*resource.Pack {
	if !pt.encryptEnabled {
		return packs
	}

	pt.mu.Lock()
	defer pt.mu.Unlock()

	out := make([]*resource.Pack, len(packs))
	for i, p := range packs {
		if p.Encrypted() {
			out[i] = p
			continue
		}
		key := generateContentKey()
		pt.generatedKeys[p.UUID().String()] = key
		out[i] = p.WithContentKey(key)
	}
	return out
}

func (pt *PackTracker) RecordDistribution(xuid, username string, packs []*resource.Pack) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	now := time.Now()
	for _, p := range packs {
		key := p.ContentKey()
		if key == "" {
			if k, ok := pt.generatedKeys[p.UUID().String()]; ok {
				key = k
			}
		}
		if key == "" {
			continue
		}
		pt.distributions = append(pt.distributions, KeyDistribution{
			XUID:       xuid,
			Username:   username,
			PackUUID:   p.UUID().String(),
			ContentKey: key,
			Time:       now,
		})
	}

	if len(pt.distributions) > 10000 {
		pt.distributions = pt.distributions[len(pt.distributions)-5000:]
	}
}

func (pt *PackTracker) LookupKeyHolder(contentKey string) []KeyDistribution {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	var matches []KeyDistribution
	for _, d := range pt.distributions {
		if d.ContentKey == contentKey {
			matches = append(matches, d)
		}
	}
	return matches
}

func generateContentKey() string {
	b := make([]byte, ContentKeyLength)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %s", err))
	}
	return hex.EncodeToString(b)[:ContentKeyLength]
}
