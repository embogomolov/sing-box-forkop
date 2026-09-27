package device

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func newObfuscatedPair(t *testing.T, obfuscation string) (*paddedPair, *Peer) {
	t.Helper()
	skA, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	skB, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pkA, pkB := skA.publicKey(), skB.publicKey()
	bindA, bindB := newChanBindPair()
	tunA, tunB := newChanTun(), newChanTun()
	devA := NewDevice(context.Background(), tunA, bindA, NewLogger(LogLevelError, "devA: "), 1)
	devB := NewDevice(context.Background(), tunB, bindB, NewLogger(LogLevelError, "devB: "), 1)
	t.Cleanup(devA.Close)
	t.Cleanup(devB.Close)
	time.Sleep(20 * time.Millisecond)
	cfgA := "private_key=" + hex.EncodeToString(skA[:]) + "\n" + obfuscation +
		fmt.Sprintf("replace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:2\nallowed_ip=%s/32\n", hex.EncodeToString(pkB[:]), testIPB)
	cfgB := "private_key=" + hex.EncodeToString(skB[:]) + "\n" + obfuscation +
		fmt.Sprintf("replace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:1\nallowed_ip=%s/32\n", hex.EncodeToString(pkA[:]), testIPA)
	if err := devA.IpcSet(cfgA); err != nil {
		t.Fatal(err)
	}
	if err := devB.IpcSet(cfgB); err != nil {
		t.Fatal(err)
	}
	if err := devA.Up(); err != nil {
		t.Fatal(err)
	}
	if err := devB.Up(); err != nil {
		t.Fatal(err)
	}
	return &paddedPair{devA: devA, devB: devB, tunA: tunA, tunB: tunB}, devA.LookupPeer(pkB)
}

func TestRandomTrailersTunnelCarriesTraffic(t *testing.T) {
	for name, obfuscation := range map[string]string{
		"random_trailers":   "random_trailers=1\n",
		"with_padding":      "random_trailers=1\ncontent_padding_addition=10-100\ns1=16\ns2=16\ns3=16\ns4=16\n",
		"header_protection": "random_trailers=1\ns1=16\ns2=16\ns3=16\ns4=16\nheader_protection_key=" + hex.EncodeToString(newHeaderKey(t)) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			pair, _ := newObfuscatedPair(t, obfuscation)
			want := buildIPv4Packet(testIPA, testIPB, 64)
			awaitPacket(t, pair.tunB, want, func() { pair.tunA.toDevice <- want })
		})
	}
}

func TestPaddedKeepaliveDoesNotArmNewHandshake(t *testing.T) {
	for name, obfuscation := range map[string]string{
		"random_trailers":          "random_trailers=1\n",
		"content_padding_addition": "content_padding_addition=32-128\n",
		"transport_padding":        "s4=16\n",
	} {
		t.Run(name, func(t *testing.T) {
			pair, peer := newObfuscatedPair(t, obfuscation)
			warmup := buildIPv4Packet(testIPA, testIPB, 16)
			awaitPacket(t, pair.tunB, warmup, func() { pair.tunA.toDevice <- warmup })
			for i := 0; i < 5; i++ {
				peer.timers.newHandshake.DelSync()
				peer.SendKeepalive()
				time.Sleep(100 * time.Millisecond)
				if peer.timers.newHandshake.IsPending() {
					t.Fatalf("keepalive %d armed the new handshake timer as if it were data", i)
				}
			}
			data := buildIPv4Packet(testIPA, testIPB, 32)
			pair.tunA.toDevice <- data
			select {
			case <-pair.tunB.fromDevice:
			case <-time.After(2 * time.Second):
				t.Fatal("data packet never arrived")
			}
			time.Sleep(100 * time.Millisecond)
			if !peer.timers.newHandshake.IsPending() {
				t.Fatal("data did not arm the new handshake timer")
			}
		})
	}
}

func TestFirstPacketCarriesTransportPaddingSetAfterStart(t *testing.T) {
	obfuscation := "s1=12\ns2=12\ns3=12\ns4=12\nheader_protection_key=" + hex.EncodeToString(newHeaderKey(t)) + "\n"
	for attempt := 0; attempt < 5; attempt++ {
		pair, _ := newObfuscatedPair(t, obfuscation)
		pair.tunA.toDevice <- buildIPv4Packet(testIPA, testIPB, 16)
		select {
		case <-pair.tunB.fromDevice:
		case <-time.After(3 * time.Second):
			t.Fatalf("the first packet after configuration was lost (attempt %d)", attempt)
		}
		pair.devA.Close()
		pair.devB.Close()
	}
}
