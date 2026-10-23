//go:build with_gvisor

package tailscale

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/types/views"
)

func TestSubnetsLeaveTheExitRoutesOut(t *testing.T) {
	routes := views.SliceOf([]netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
		netip.MustParsePrefix("fd00:1::/64"),
	})
	if got, want := subnets(&ipnstate.PeerStatus{PrimaryRoutes: &routes}), []string{"192.168.1.0/24", "fd00:1::/64"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	if got := subnets(&ipnstate.PeerStatus{}); got != nil {
		t.Fatalf("a device that shares nothing got %v", got)
	}
}
