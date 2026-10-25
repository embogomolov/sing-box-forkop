package route

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type groupTestOutbound struct {
	outbound.Adapter
}

func newGroupTestOutbound(outboundType string, tag string) groupTestOutbound {
	return groupTestOutbound{outbound.NewAdapter(outboundType, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil)}
}

func (o *groupTestOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, E.New("not dialed")
}

func (o *groupTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("not dialed")
}

type groupTestSelector struct {
	groupTestOutbound
	selected adapter.Outbound
}

func (g *groupTestSelector) All() []string                     { return []string{g.selected.Tag()} }
func (g *groupTestSelector) Selected(string) adapter.Outbound  { return g.selected }
func (g *groupTestSelector) AttachConnection(io.Closer) func() { return func() {} }

type groupTestDialingGroup struct {
	groupTestSelector
}

func (g *groupTestDialingGroup) DialsMembers() {}

// A group that dials its members itself is where the chain ends: the router dials the group,
// which moves on to another member when the one it reports fails.
func TestResolveOutboundStopsAtAGroupThatDialsItsMembers(t *testing.T) {
	nodeOutbound := newGroupTestOutbound("vless", "node")
	node := &nodeOutbound
	fallback := &groupTestDialingGroup{groupTestSelector{newGroupTestOutbound("fallback", "fallback"), node}}
	selector := &groupTestSelector{newGroupTestOutbound("selector", "selector"), fallback}

	chain, err := resolveOutbound(selector, N.NetworkTCP)
	require.NoError(t, err)
	require.Equal(t, []adapter.Outbound{selector, fallback}, chain)

	selector.selected = node
	chain, err = resolveOutbound(selector, N.NetworkUDP)
	require.NoError(t, err)
	require.Equal(t, []adapter.Outbound{selector, node}, chain)
}
