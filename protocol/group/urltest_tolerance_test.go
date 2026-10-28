package group

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

func TestURLTestToleranceOverflow(t *testing.T) {
	current := newTypedTestOutbound(C.TypeDirect, "current")
	slower := newTypedTestOutbound(C.TypeDirect, "slower")
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory(current.Tag(), &adapter.URLTestHistory{Delay: 500})
	history.StoreURLTestHistory(slower.Tag(), &adapter.URLTestHistory{Delay: 1000})
	group := &URLTestGroup{
		outbounds: []adapter.Outbound{current, slower}, history: history, tolerance: 65000,
		selectedOutboundTCP: current, selectedOutboundUDP: current,
	}
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		if selected, ok := group.Select(network); selected != current || !ok {
			t.Fatalf("%s: overflow selected %v instead of the current member", network, selected)
		}
	}
}
