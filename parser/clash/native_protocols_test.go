package clash

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestNativeProtocolOptions(t *testing.T) {
	result := parse(t, `proxies:
  - {name: mieru, type: mieru, server: example.org, port: 443, username: alice, password: secret, transport: UDP, mtu: 1280, handshake-mode: HANDSHAKE_NO_WAIT}
  - {name: hy2, type: hysteria2, server: example.org, port: 443, password: secret, obfs: gecko, obfs-password: secret, hop-interval: 30-60, bbr-profile: conservative, disable-chrome-parrot: true}
  - {name: snell6, type: snell, server: example.org, port: 443, psk: secret, version: 6, userkey: user-key, mode: unshaped}
  - {name: snell5, type: snell, server: example.org, port: 443, psk: secret, version: 5, obfs-opts: {mode: http, host: example.org}}
`)
	require.Empty(t, result.Skipped)
	require.Len(t, result.Outbounds, 4)
	mieru := result.Outbounds[0].Options.(*option.MieruOutboundOptions)
	require.Equal(t, uint32(1280), mieru.MTU)
	require.Equal(t, "HANDSHAKE_NO_WAIT", mieru.HandshakeMode)
	require.Equal(t, "UDP", mieru.Transport)
	hy2 := result.Outbounds[1].Options.(*option.Hysteria2OutboundOptions)
	require.Equal(t, "gecko", hy2.Obfs.Type)
	require.Equal(t, 30*time.Second, time.Duration(hy2.HopInterval))
	require.Equal(t, 60*time.Second, time.Duration(hy2.HopIntervalMax))
	require.Equal(t, "conservative", hy2.BBRProfile)
	require.True(t, hy2.DisableChromeParrot)
	snell6 := result.Outbounds[2].Options.(*option.SnellOutboundOptions)
	require.Equal(t, "user-key", snell6.UserKey)
	require.Equal(t, "unshaped", snell6.V6Options.Mode)
	snell5 := result.Outbounds[3].Options.(*option.SnellOutboundOptions)
	require.Equal(t, 4, snell5.Version)
	require.Equal(t, "http", snell5.ObfsOptions.ObfsMode)
}

func TestLegacySnellDoesNotSilentlyChangeWireProtocol(t *testing.T) {
	result := parse(t, `proxies:
  - {name: default, type: snell, server: example.org, port: 443, psk: secret}
  - {name: legacy, type: snell, server: example.org, port: 443, psk: secret, version: 3}
  - {name: wrong-mode, type: snell, server: example.org, port: 443, psk: secret, version: 4, mode: unshaped}
`)
	require.Empty(t, result.Outbounds)
	require.Len(t, result.Skipped, 3)
}
