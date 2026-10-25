package mieru

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// markOutbound refuses every dial and notes whether it was asked for an external connection.
type markOutbound struct {
	outbound.Adapter
	access   sync.Mutex
	external []bool
}

func (o *markOutbound) record(ctx context.Context) {
	o.access.Lock()
	o.external = append(o.external, interrupt.IsExternalConnectionFromContext(ctx))
	o.access.Unlock()
}

func (o *markOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.record(ctx)
	return nil, E.New("refused")
}

func (o *markOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	o.record(ctx)
	return nil, os.ErrInvalid
}

type markOutboundManager struct {
	adapter.OutboundManager
	outbound adapter.Outbound
}

func (m *markOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	return m.outbound, tag == m.outbound.Tag()
}

// underlayMarks opens a connection as an external one would and returns the marks of its underlay dials.
func underlayMarks(t *testing.T, transport string, multiplexing string) []bool {
	detour := &markOutbound{Adapter: outbound.NewAdapter("test", "detour", []string{N.NetworkTCP, N.NetworkUDP}, nil)}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), &markOutboundManager{outbound: detour})
	logger := log.NewNOPFactory().Logger()
	instance, err := NewOutbound(ctx, nil, logger, "mieru", option.MieruOutboundOptions{
		DialerOptions: option.DialerOptions{Detour: "detour"},
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 4443},
		Transport:     transport,
		UserName:      "user",
		Password:      "secret",
		Multiplexing:  multiplexing,
	})
	require.NoError(t, err)
	scope := adapter.NewScope(ctx, logger)
	defer scope.Close()
	require.NoError(t, instance.(*Outbound).Start(adapter.StartStatePostStart, scope))
	_, err = instance.DialContext(interrupt.ContextWithIsExternalConnection(context.Background(), true), N.NetworkTCP, M.ParseSocksaddr("1.1.1.1:443"))
	require.Error(t, err)
	detour.access.Lock()
	defer detour.access.Unlock()
	return detour.external
}

// A group switching members without interrupt_exist_connections closes only internal connections.
// With multiplexing off an underlay carries one connection and keeps its mark.
func TestSharedUnderlayIsInternal(t *testing.T) {
	for _, transport := range []string{"TCP", "UDP"} {
		require.Equal(t, []bool{false}, underlayMarks(t, transport, ""), transport)
		require.Equal(t, []bool{false}, underlayMarks(t, transport, "MULTIPLEXING_HIGH"), transport)
		require.Equal(t, []bool{true}, underlayMarks(t, transport, "MULTIPLEXING_OFF"), transport)
	}
}
