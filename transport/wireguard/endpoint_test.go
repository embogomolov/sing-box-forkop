package wireguard

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestAmneziaIPCSerialization(t *testing.T) {
	keepalive := option.Range[uint32]{From: 15, To: 25}
	lines := (peerConfig{publicKeyHex: "public", keepalive: &keepalive}).GenerateIpcLines()
	if !strings.Contains(lines, "\npersistent_keepalive_interval=15-25") {
		t.Fatalf("unexpected Amnezia keepalive IPC: %q", lines)
	}
}

func TestDefaultMTUMakesRoomForTransportPadding(t *testing.T) {
	for _, test := range []struct {
		amnezia *AmneziaOptions
		mtu     uint32
	}{
		{nil, 1408},
		{&AmneziaOptions{S1: 30}, 1408},
		{&AmneziaOptions{S4: 27}, 1381},
		{&AmneziaOptions{S4: 500}, 1280},
	} {
		if mtu := defaultMTU(test.amnezia); mtu != test.mtu {
			t.Fatalf("default MTU with %+v: %d, want %d", test.amnezia, mtu, test.mtu)
		}
	}
}

func TestAmneziaHeaderProtectionKeyLength(t *testing.T) {
	_, err := NewEndpoint(EndpointOptions{
		PrivateKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		Amnezia: &AmneziaOptions{
			HeaderProtectionKey: base64.StdEncoding.EncodeToString(make([]byte, 31)),
		},
	})
	// Without the message the test would also pass on a build with no device to create.
	if err == nil || !strings.Contains(err.Error(), "header protection key length") {
		t.Fatalf("invalid Amnezia header protection key length was accepted: %v", err)
	}
}
