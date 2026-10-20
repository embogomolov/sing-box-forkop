package wireguard

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/wireguard"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// WARP builds its WireGuard endpoints from goroutines, so the first lookups of
// a box can race; they must still agree on one registry, and a registry must
// never outlive or cross into another box.
func TestDeviceRegistryIsOnePerBox(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	registries := make([]*deviceRegistry, 16)
	var group sync.WaitGroup
	for i := range registries {
		group.Add(1)
		go func() {
			defer group.Done()
			registries[i] = deviceRegistryFromContext(ctx)
		}()
	}
	group.Wait()
	for _, registry := range registries {
		require.Same(t, registries[0], registry)
	}
	require.NotSame(t, registries[0], deviceRegistryFromContext(service.ContextWithDefaultRegistry(context.Background())))
	require.Nil(t, deviceRegistryFromContext(context.Background()))
}

func sampleDeviceOptions() (option.WireGuardCommonOptions, *wireguard.AmneziaOptions) {
	return option.WireGuardCommonOptions{
			MTU:        1280,
			Address:    badoption.Listable[netip.Prefix]{netip.MustParsePrefix("10.8.1.5/32")},
			PrivateKey: "client-key",
			Peers: []option.WireGuardPeer{{
				Address:    "203.0.113.1",
				Port:       51820,
				PublicKey:  "server-key",
				AllowedIPs: badoption.Listable[netip.Prefix]{netip.MustParsePrefix("0.0.0.0/0")},
			}},
		}, &wireguard.AmneziaOptions{
			JC: 5,
			S4: 12,
		}
}

// The key decides which endpoints run on one device, so every setting of the
// device has to reach it; an option type that serialised only part of itself
// would merge endpoints that are not the same.
func TestSharedDeviceKeyCoversEverySetting(t *testing.T) {
	options, amnezia := sampleDeviceOptions()
	base, identities, err := sharedDeviceKey("amneziawg", options, amnezia)
	require.NoError(t, err)
	require.Equal(t, []string{"client-key/server-key"}, identities)

	again, _, err := sharedDeviceKey("amneziawg", options, amnezia)
	require.NoError(t, err)
	require.Equal(t, base, again)

	for name, change := range map[string]func(*string, *option.WireGuardCommonOptions, *wireguard.AmneziaOptions){
		"type": func(endpointType *string, _ *option.WireGuardCommonOptions, _ *wireguard.AmneziaOptions) {
			*endpointType = "wireguard"
		},
		"mtu": func(_ *string, it *option.WireGuardCommonOptions, _ *wireguard.AmneziaOptions) { it.MTU = 1420 },
		"address": func(_ *string, it *option.WireGuardCommonOptions, _ *wireguard.AmneziaOptions) {
			it.Address = badoption.Listable[netip.Prefix]{netip.MustParsePrefix("10.8.1.6/32")}
		},
		"private key": func(_ *string, it *option.WireGuardCommonOptions, _ *wireguard.AmneziaOptions) {
			it.PrivateKey = "other-client-key"
		},
		"detour": func(_ *string, it *option.WireGuardCommonOptions, _ *wireguard.AmneziaOptions) { it.Detour = "Proxy" },
		"bind interface": func(_ *string, it *option.WireGuardCommonOptions, _ *wireguard.AmneziaOptions) {
			it.BindInterface = "wan"
		},
		"peer address": func(_ *string, it *option.WireGuardCommonOptions, _ *wireguard.AmneziaOptions) {
			it.Peers = []option.WireGuardPeer{{Address: "203.0.113.2", Port: 51820, PublicKey: "server-key"}}
		},
		"peer key": func(_ *string, it *option.WireGuardCommonOptions, _ *wireguard.AmneziaOptions) {
			it.Peers = []option.WireGuardPeer{{Address: "203.0.113.1", Port: 51820, PublicKey: "other-server-key"}}
		},
		"obfuscation": func(_ *string, _ *option.WireGuardCommonOptions, it *wireguard.AmneziaOptions) { it.S4 = 16 },
	} {
		t.Run(name, func(t *testing.T) {
			endpointType := "amneziawg"
			changedOptions, changedAmnezia := sampleDeviceOptions()
			change(&endpointType, &changedOptions, changedAmnezia)
			changed, _, err := sharedDeviceKey(endpointType, changedOptions, changedAmnezia)
			require.NoError(t, err)
			require.NotEqual(t, base, changed)
		})
	}
}
