package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
)

func main() {
	addr := "127.0.0.1:19132"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	fmt.Printf("Connecting to %s as a fake bedrocktool client...\n", addr)

	dialer := minecraft.Dialer{
		ClientData: login.ClientData{
			DeviceOS:         protocol.DeviceAndroid,
			DeviceModel:      "",
			UIProfile:        0,
			CurrentInputMode: 1,
			DefaultInputMode: 1,
			PlatformOnlineID: "",
			GUIScale:         0,
			LanguageCode:     "en_US",
			GameVersion:      "1.21.50",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "raknet", addr)
	if err != nil {
		fmt.Printf("Connection failed (expected if blocked): %s\n", err)
		return
	}
	defer conn.Close()

	packs := conn.ResourcePacks()
	fmt.Printf("Connected! Received %d resource packs\n", len(packs))
	if len(packs) == 0 {
		fmt.Println(">> PackGuard returned EMPTY packs — detection worked!")
	} else {
		fmt.Println(">> Received packs (not blocked)")
		for _, p := range packs {
			fmt.Printf("   - %s v%s\n", p.Name(), p.Version())
		}
	}
}
