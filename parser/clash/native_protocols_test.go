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

func TestTrustTunnelOptions(t *testing.T) {
	result := parse(t, `proxies:
  - {name: h2, type: trusttunnel, server: 203.0.113.5, port: 443, username: alice, password: secret, sni: vpn.example.org, client-fingerprint: chrome, udp: true, health-check: true}
  - {name: h3, type: trusttunnel, server: vpn.example.org, port: 8443, username: alice, password: secret, quic: true, congestion-controller: new_reno, client-fingerprint: chrome, max-connections: 4}
  - {name: renamed, type: trusttunnel, server: vpn.example.org, port: 443, username: alice, password: secret, name-cert-verify: other.example.org}
  - {name: anonymous, type: trusttunnel, server: vpn.example.org, port: 443, username: alice}
`)
	require.Len(t, result.Outbounds, 2)
	require.Len(t, result.Skipped, 2)
	h2 := result.Outbounds[0].Options.(*option.TrustTunnelOutboundOptions)
	require.Equal(t, "203.0.113.5", h2.Server)
	require.Equal(t, "vpn.example.org", h2.TLS.ServerName)
	require.Equal(t, "chrome", h2.TLS.UTLS.Fingerprint)
	require.Empty(t, h2.Network)
	require.True(t, h2.HealthCheck)
	require.False(t, h2.QUIC)
	h3 := result.Outbounds[1].Options.(*option.TrustTunnelOutboundOptions)
	require.True(t, h3.QUIC)
	require.Equal(t, "reno", h3.QUICCongestionControl)
	require.Nil(t, h3.TLS.UTLS)
	require.Equal(t, "tcp", string(h3.Network))
}
