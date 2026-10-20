//go:build with_gvisor

package wireguard

import (
	"context"
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func TestAmneziaFlagsReachDevice(t *testing.T) {
	direct, err := dialer.NewDefault(context.Background(), option.DialerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := NewEndpoint(EndpointOptions{
		Context:    context.Background(),
		Logger:     log.NewNOPFactory().NewLogger("test"),
		Dialer:     direct,
		Address:    []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
		PrivateKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32))),
		Amnezia: &AmneziaOptions{
			RandomTrailers: true,
			DisableCookies: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	if err := endpoint.Start(false); err != nil {
		t.Fatal(err)
	}
	state, err := endpoint.device.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(state, "random_trailers=1\n") || !strings.Contains(state, "disable_cookies=1\n") {
		t.Fatal("AmneziaWG 3.1 flags did not reach the device")
	}
}
