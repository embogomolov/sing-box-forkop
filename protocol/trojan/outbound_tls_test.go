package trojan

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestOutboundWithDisabledTLSDialsPlainTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	outbound, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test", option.TrojanOutboundOptions{
		ServerOptions:               option.ServerOptions{Server: "127.0.0.1", ServerPort: port},
		Password:                    "password",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: false}},
	})
	require.NoError(t, err)
	conn, err := outbound.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:80"))
	require.NoError(t, err)
	conn.Close()
}
