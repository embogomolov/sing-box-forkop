package trusttunnel

import (
	"context"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func validOutboundOptions() option.TrustTunnelOutboundOptions {
	return option.TrustTunnelOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		Username:      "user",
		Password:      "secret",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: "vpn.example.com"},
		},
	}
}

func TestOutboundValidation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		modify func(options *option.TrustTunnelOutboundOptions)
		want   string
	}{
		{"tls missing", func(options *option.TrustTunnelOutboundOptions) { options.TLS = nil }, C.ErrTLSRequired.Error()},
		{"tls disabled", func(options *option.TrustTunnelOutboundOptions) { options.TLS.Enabled = false }, C.ErrTLSRequired.Error()},
		{"ip server without server_name", func(options *option.TrustTunnelOutboundOptions) { options.TLS.ServerName = "" }, "tls.server_name is required"},
		{"ipv6 server without server_name", func(options *option.TrustTunnelOutboundOptions) {
			options.Server = "::1"
			options.TLS.ServerName = ""
		}, "tls.server_name is required"},
		{"empty username", func(options *option.TrustTunnelOutboundOptions) { options.Username = "" }, "missing username"},
		{"empty password", func(options *option.TrustTunnelOutboundOptions) { options.Password = "" }, "missing password"},
		{"icmp", func(options *option.TrustTunnelOutboundOptions) { options.Network = "tcp\nicmp" }, "unsupported network: icmp"},
		{"quic with utls", func(options *option.TrustTunnelOutboundOptions) {
			options.QUIC = true
			options.TLS.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}
		}, "uTLS is not supported with quic"},
		{"bad congestion control", func(options *option.TrustTunnelOutboundOptions) { options.QUICCongestionControl = "bbr2" }, "unknown quic_congestion_control: bbr2"},
		{"alpn without h2", func(options *option.TrustTunnelOutboundOptions) {
			options.TLS.ALPN = badoption.Listable[string]{"http/1.1"}
		}, "tls.alpn must contain h2"},
		{"alpn without h3 on quic", func(options *option.TrustTunnelOutboundOptions) {
			options.QUIC = true
			options.TLS.ALPN = badoption.Listable[string]{"h2"}
		}, "tls.alpn must contain h3"},
	}
	for _, testCase := range cases {
		options := validOutboundOptions()
		testCase.modify(&options)
		_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "tt", options)
		if err == nil || !strings.Contains(err.Error(), testCase.want) {
			t.Errorf("%s: expected %q, got %v", testCase.name, testCase.want, err)
		}
	}
}

// A domain server needs the box's DNS managers in the context (dial fields);
// the stand covers it, these cases stay on an IP literal.
func TestOutboundAcceptsValidOptions(t *testing.T) {
	t.Parallel()
	for _, modify := range []func(options *option.TrustTunnelOutboundOptions){
		func(options *option.TrustTunnelOutboundOptions) {},
		func(options *option.TrustTunnelOutboundOptions) {
			options.TLS.ALPN = badoption.Listable[string]{"h2", "http/1.1"}
		},
		func(options *option.TrustTunnelOutboundOptions) {
			options.Network = "udp"
			options.QUICCongestionControl = "reno"
		},
	} {
		options := validOutboundOptions()
		modify(&options)
		outbound, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "tt", options)
		if err != nil {
			t.Fatalf("%+v: %v", options, err)
		}
		if outbound.Type() != C.TypeTrustTunnel {
			t.Fatalf("type = %s", outbound.Type())
		}
		outbound.(*Outbound).Close()
	}
}

func TestOutboundIdleWindow(t *testing.T) {
	t.Parallel()
	duration := func(value time.Duration) *badoption.Duration {
		converted := badoption.Duration(value)
		return &converted
	}
	cases := []struct {
		node *badoption.Duration
		want time.Duration
	}{
		{nil, defaultIdleTimeout},
		{duration(2 * time.Minute), 2 * time.Minute},
		{duration(0), 0},
	}
	for _, testCase := range cases {
		if got := idleWindow(testCase.node); got != testCase.want {
			t.Errorf("idleWindow(%v) = %v, want %v", testCase.node, got, testCase.want)
		}
	}
}

// markOutbound refuses every dial and notes whether it was asked for an external connection.
type markOutbound struct {
	outbound.Adapter
	access   sync.Mutex
	external []bool
}

func (o *markOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.access.Lock()
	o.external = append(o.external, interrupt.IsExternalConnectionFromContext(ctx))
	o.access.Unlock()
	return nil, E.New("refused")
}

func (o *markOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

type markOutboundManager struct {
	adapter.OutboundManager
	outbound adapter.Outbound
}

func (m *markOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	return m.outbound, tag == m.outbound.Tag()
}

// A group switching members without interrupt_exist_connections closes only internal connections; an
// external session would carry the streams opened after the switch through the old member.
func TestOutboundSessionIsInternal(t *testing.T) {
	for _, quic := range []bool{false, true} {
		if quic && !C.WithQUIC {
			continue
		}
		detour := &markOutbound{Adapter: outbound.NewAdapter("test", "detour", []string{N.NetworkTCP, N.NetworkUDP}, nil)}
		ctx := service.ContextWith[adapter.OutboundManager](context.Background(), &markOutboundManager{outbound: detour})
		options := validOutboundOptions()
		options.Detour = "detour"
		options.QUIC = quic
		instance, err := NewOutbound(ctx, nil, log.NewNOPFactory().Logger(), "tt", options)
		if err != nil {
			t.Fatal(err)
		}
		_, err = instance.DialContext(interrupt.ContextWithIsExternalConnection(context.Background(), true), N.NetworkTCP, M.ParseSocksaddr("1.1.1.1:443"))
		instance.(*Outbound).Close()
		if err == nil {
			t.Fatalf("quic %v: a refused session dial opened a stream", quic)
		}
		detour.access.Lock()
		if !slices.Equal(detour.external, []bool{false}) {
			t.Errorf("quic %v: session dials marked external %v, want one internal", quic, detour.external)
		}
		detour.access.Unlock()
	}
}

// A URL test warms the session up first, so that its delay leaves out the session's handshakes.
func TestOutboundReportsSession(t *testing.T) {
	instance, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "tt", validOutboundOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer instance.(*Outbound).Close()
	multiplexOutbound, isMultiplex := common.Cast[adapter.OutboundWithMultiplex](instance)
	if !isMultiplex || !multiplexOutbound.MultiplexEnabled() {
		t.Fatal("TrustTunnel did not report its session")
	}
}
